#!/usr/bin/env python3
"""
collect.py — build data.json for the cohort CloudTrail dashboard.

Pulls CloudTrail management events over a rolling window, attributes each call
to an IAM user, maps that user to one of two IAM groups, and aggregates the
signals the dashboard renders (calls, errors, denials, regions, access method,
costly intent, daily timeline, cohort heatmap).

PORTABILITY
-----------
Credentials come from the standard boto3 chain, so the SAME script runs:
  - locally on WSL using your configured profile  (AWS_PROFILE=... or --profile)
  - in AWS on an EC2/ECS/Lambda role              (no flags, no code change)
Nothing here is environment-specific except what you pass on the CLI.

USAGE
-----
  # local WSL, using a named profile
  python3 collect.py \
      --groups devsecops-track sre-track \
      --region ap-southeast-1 \
      --days 30 \
      --profile my-sso-profile \
      --out data.json

  # in AWS on an instance/task role (uses ambient creds + region)
  python3 collect.py --groups devsecops-track sre-track --days 30 --out data.json

Requires: boto3  (pip install boto3)
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# Events that signal potential spend, with rough relative weights.
COSTLY_WEIGHTS = {
    "RunInstances": 3,
    "CreateCluster": 8,
    "CreateNatGateway": 5,
    "AllocateAddress": 1,
    "CreateLoadBalancer": 3,
    "CreateDBInstance": 6,
    "CreateVolume": 1,
}

# errorCode values that mean "blocked by policy".
DENY_CODES = {
    "AccessDenied", "AccessDeniedException",
    "UnauthorizedOperation", "Client.UnauthorizedOperation",
    "Forbidden",
}

GROUP_COLORS = ["#3D3BD6", "#1F9D72", "#C2841A", "#7A3DD6"]


def session_for(profile, region):
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def map_users_to_groups(sess, group_names):
    """Return {iam_username: group_id} for every user in the named groups."""
    iam = sess.client("iam")
    user_group = {}
    for g in group_names:
        try:
            paginator = iam.get_paginator("get_group")
            for page in paginator.paginate(GroupName=g):
                for u in page.get("Users", []):
                    user_group[u["UserName"]] = g
        except ClientError as e:
            print(f"  ! could not read group '{g}': {e}", file=sys.stderr)
    return user_group


def classify_access(user_agent):
    ua = (user_agent or "").lower()
    if "console.amazonaws.com" in ua or "signin.amazonaws.com" in ua or "aws internal" in ua:
        return "console"
    if "terraform" in ua or "hashicorp" in ua:
        return "terraform"
    if "aws-cli" in ua or "boto3" in ua or "botocore" in ua or "aws-sdk" in ua:
        return "sdk"
    return "other"


def load_cache(path):
    """Read the incremental event cache (JSONL). Returns a list of records with
    'eventTime' parsed to an aware datetime. Missing/corrupt file -> []."""
    records = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    obj["t"] = datetime.strptime(obj["t"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                    records.append(obj)
                except (ValueError, KeyError):
                    continue  # skip a bad line rather than abort the whole run
    except FileNotFoundError:
        return []
    return records


def save_cache(path, records):
    """Write records (each {'id','t','u','r','ev'}) to JSONL atomically."""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        for rec in records:
            f.write(json.dumps({
                "id": rec["id"],
                "t": rec["t"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "u": rec["u"], "r": rec["r"], "ev": rec["ev"],
            }) + "\n")
    os.replace(tmp, path)  # atomic swap so a crash never leaves a half-written cache


def load_cache_meta(path):
    """Read the cache coverage sidecar: {'covers_from', 'watermark'} as aware
    datetimes, or None if absent/corrupt. Coverage must be tracked explicitly —
    it can't be inferred from event timestamps, since a quiet period legitimately
    has no events near the window start."""
    try:
        with open(path + ".meta") as f:
            obj = json.load(f)
        return {
            "covers_from": datetime.strptime(obj["covers_from"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
            "watermark": datetime.strptime(obj["watermark"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
        }
    except (FileNotFoundError, ValueError, KeyError):
        return None


def save_cache_meta(path, covers_from, watermark):
    tmp = path + ".meta.tmp"
    with open(tmp, "w") as f:
        json.dump({
            "covers_from": covers_from.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "watermark": watermark.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }, f)
    os.replace(tmp, path + ".meta")


def collect(args):
    t_auth = time.monotonic()
    sess = session_for(args.profile, args.region)
    region = sess.region_name or args.region or "us-east-1"
    sts = sess.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    print(f"  [timing] auth + STS identity: {time.monotonic() - t_auth:.1f}s", file=sys.stderr, flush=True)

    # Per-group home region (parallel to --groups). Defaults to session region.
    home_regions = args.home_regions or []
    group_home = {}
    for i, g in enumerate(args.groups):
        group_home[g] = home_regions[i] if i < len(home_regions) else region

    # Regions to actually query CloudTrail in. LookupEvents is REGIONAL, so to
    # see both groups we must scan every region any group works in (plus any
    # extra sprawl regions passed via --scan-regions).
    scan_regions = sorted(set((args.scan_regions or []) + list(group_home.values())))

    mode = "writes only (readOnly=false)" if args.writes_only else "all events"
    print(f"Account {account_id} · scanning {scan_regions} · window {args.days}d · {mode}", file=sys.stderr)
    t_map = time.monotonic()
    user_group = map_users_to_groups(sess, args.groups)
    if not user_group:
        print("No users found in the given groups. Check --groups names.", file=sys.stderr)
    print(f"Mapped {len(user_group)} principals across {len(args.groups)} groups "
          f"[timing] iam:GetGroup: {time.monotonic() - t_map:.1f}s", file=sys.stderr, flush=True)

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=args.days)
    # daily[] has one slot per day, oldest -> newest, with the LAST slot = today.
    # Bucket relative to this origin so today lands at index args.days-1; the few
    # hours older than the origin (day_idx < 0) fall outside the array and are
    # skipped by the guard below. (Using start.date() instead would push today to
    # index args.days and silently drop the most recent day.)
    daily_origin = now.date() - timedelta(days=args.days - 1)

    # per-user accumulators
    def new_acc():
        return {
            "total_calls": 0, "error_calls": 0, "denied_calls": 0,
            "first_active": None, "last_active": None,
            "services": defaultdict(int), "events": defaultdict(int),
            "regions": defaultdict(int),
            "access": {"console": 0, "terraform": 0, "sdk": 0, "other": 0},
            "daily": [0] * args.days,
            "denials": defaultdict(int),
            "costly": defaultdict(int),
        }

    accs = defaultdict(new_acc)
    heatmap = [[0] * 24 for _ in range(7)]  # 0=Mon..6=Sun, UTC
    seen = 0
    matched = 0

    # Query CloudTrail once per student using a server-side Username filter, so we
    # only page through events for members of the two IAM groups instead of the
    # whole account's activity. On a busy shared account this is dramatically
    # fewer pages. Trade-off: the Username attribute matches the user name that
    # CloudTrail records (IAM user name, or the role-session name for assumed
    # roles) — activity under an assumed role whose session name differs from the
    # IAM user name won't be captured.
    #
    # For home regions, only query the users whose group lives there (group-a
    # users in ap-southeast-1 only, group-b users in us-east-1 only). For extra
    # --scan-regions (sprawl detection), query all users since we're looking for
    # anyone who has strayed into that region.
    home_region_set = set(group_home.values())

    # Build the full (region, username) work list up front: each home region gets
    # only its own group's members; --scan-regions extras get everyone.
    tasks = []  # (scan_region, uname)
    for scan_region in scan_regions:
        if scan_region in home_region_set:
            region_usernames = sorted(u for u in user_group if group_home[user_group[u]] == scan_region)
        else:
            region_usernames = sorted(user_group)
        tasks.extend((scan_region, u) for u in region_usernames)

    # One CloudTrail client per region (low-level boto3 clients are thread-safe
    # for making calls, so worker threads share them safely).
    clients = {
        r: sess.client("cloudtrail", region_name=r,
                       config=Config(retries={"max_attempts": 10, "mode": "adaptive"}))
        for r in scan_regions
    }

    # ---- Incremental cache ---------------------------------------------------
    # CloudTrail events are immutable, so re-downloading the whole window every run
    # is wasted work. We persist every fetched raw event (keyed by eventID) and on
    # the next run only fetch events newer than the last run's watermark, minus a
    # safety overlap for CloudTrail's ingestion lag (events can surface a few
    # minutes after they happen; dedup by eventID makes the overlap harmless).
    # The cache stores ALL events PRE-writes_only filter, so a later all-events run
    # isn't poisoned by an earlier --writes-only one — the readOnly filter is
    # applied at aggregation time, not at cache time.
    window_start = start
    cache_records = {}                 # eventID -> record, reused from disk
    fetch_start = window_start         # how far back this run actually queries
    use_cache = bool(args.cache) and not args.no_cache
    if use_cache:
        meta = load_cache_meta(args.cache)
        in_window = {r["id"]: r for r in load_cache(args.cache) if window_start <= r["t"] <= now}
        # Trust the cache only if its recorded coverage reaches back to (or before)
        # this run's window start. Coverage comes from the sidecar, not the events,
        # so a quiet stretch with no events near window_start is still trusted.
        if meta and meta["covers_from"] <= window_start:
            watermark = meta["watermark"]
            fetch_start = max(window_start, watermark - timedelta(minutes=args.cache_overlap_min))
            cache_records = in_window
            print(f"  [cache] {len(in_window)} cached events in window · delta fetch from "
                  f"{fetch_start:%Y-%m-%dT%H:%M:%SZ} (watermark {watermark:%Y-%m-%dT%H:%M:%SZ} "
                  f"− {args.cache_overlap_min}m)", file=sys.stderr, flush=True)
        elif meta:
            print(f"  [cache] coverage starts {meta['covers_from']:%Y-%m-%d}, after window start "
                  f"{window_start:%Y-%m-%d} (wider window) — full re-fetch this run", file=sys.stderr, flush=True)
        else:
            print("  [cache] cold (no coverage metadata) — full fetch this run", file=sys.stderr, flush=True)

    # Worker: pure network I/O. Pages one user's events in one region from
    # fetch_start and returns the raw CloudTrailEvent JSON strings. NO shared
    # mutable state is touched here — merge + aggregation happen single-threaded
    # below, so accs/heatmap need no locks.
    def fetch(task):
        scan_region, uname = task
        paginator = clients[scan_region].get_paginator("lookup_events")
        raw_events = []
        pages_n = 0
        t0 = time.monotonic()
        try:
            pages = paginator.paginate(
                StartTime=fetch_start, EndTime=now,
                LookupAttributes=[{"AttributeKey": "Username", "AttributeValue": uname}],
            )
            for page in pages:
                pages_n += 1
                for ev in page.get("Events", []):
                    raw = ev.get("CloudTrailEvent")
                    if raw is not None:
                        raw_events.append(raw)
        except ClientError as e:
            return scan_region, uname, raw_events, e, pages_n, time.monotonic() - t0
        return scan_region, uname, raw_events, None, pages_n, time.monotonic() - t0

    def make_record(uname, scan_region, raw):
        """Parse a raw CloudTrailEvent into a cache record, or None if unusable."""
        try:
            detail = json.loads(raw)
        except ValueError:
            return None
        et = detail.get("eventTime")
        try:
            ts = datetime.strptime(et, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            ts = now
        eid = detail.get("eventID") or f"{uname}|{et}|{detail.get('eventName')}"
        return {"id": eid, "t": ts, "u": uname, "r": scan_region, "ev": raw}

    print(f"  fetching {len(tasks)} (region, user) queries with {args.max_workers} workers...",
          file=sys.stderr, flush=True)

    t_fetch = time.monotonic()
    timings = []           # (elapsed, region, uname, pages, events) — for slowest-N report
    fetched = {}           # eventID -> record, freshly pulled this run
    done = 0
    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        futures = [pool.submit(fetch, t) for t in tasks]
        for fut in as_completed(futures):
            scan_region, uname, raw_events, err, pages_n, elapsed = fut.result()
            timings.append((elapsed, scan_region, uname, pages_n, len(raw_events)))
            done += 1
            if err is not None:
                print(f"  ! CloudTrail error for {uname} in {scan_region}: {err}", file=sys.stderr)
            for raw in raw_events:
                rec = make_record(uname, scan_region, raw)
                if rec is not None:
                    fetched[rec["id"]] = rec
            if done % 10 == 0 or done == len(tasks):
                print(f"    {done}/{len(tasks)} queries done, {len(fetched)} new events so far...",
                      file=sys.stderr, flush=True)

    fetch_wall = time.monotonic() - t_fetch

    # Merge cache + fresh (fresh wins on eventID collisions), then aggregate once
    # over the union — single-threaded, so accs/heatmap/counters stay race-free.
    combined = dict(cache_records)
    combined.update(fetched)

    def ingest(uname, scan_region, raw, ts):
        """Fold one event into the per-user accumulators. Returns False if the
        event is unusable or dropped by --writes-only."""
        try:
            detail = json.loads(raw)
        except ValueError:
            return False
        # LookupEvents allows only ONE attribute per call and we already spend it
        # on Username, so the readOnly filter is applied here, at aggregation time
        # (keeping the cache complete). Same flag the server-side ReadOnly uses;
        # drop only events explicitly marked read-only (keep ambiguous ones).
        if args.writes_only and detail.get("readOnly") is True:
            return False
        a = accs[uname]
        a["total_calls"] += 1
        if a["first_active"] is None or ts < a["first_active"]:
            a["first_active"] = ts
        if a["last_active"] is None or ts > a["last_active"]:
            a["last_active"] = ts
        day_idx = (ts.date() - daily_origin).days
        if 0 <= day_idx < args.days:
            a["daily"][day_idx] += 1
        heatmap[ts.weekday()][ts.hour] += 1
        svc = (detail.get("eventSource") or "").replace(".amazonaws.com", "")
        name = detail.get("eventName") or "?"
        if svc:
            a["services"][svc] += 1
        a["events"][name] += 1
        a["regions"][detail.get("awsRegion") or scan_region] += 1
        a["access"][classify_access(detail.get("userAgent"))] += 1
        err_code = detail.get("errorCode")
        if err_code:
            a["error_calls"] += 1
            if err_code in DENY_CODES:
                a["denied_calls"] += 1
                action = f"{svc}:{name}" if svc else name
                a["denials"][action] += 1
        if name in COSTLY_WEIGHTS:
            a["costly"][name] += 1
        return True

    for rec in combined.values():
        # Guard the window edges and ignore any cached users no longer in --groups
        # (e.g. cache reused after a roster/groups change).
        if rec["t"] < window_start or rec["t"] > now or rec["u"] not in user_group:
            continue
        seen += 1
        if ingest(rec["u"], rec["r"], rec["ev"], rec["t"]):
            matched += 1

    # Persist the merged, window-pruned set so the cache stays bounded and the
    # next run can fetch only the delta.
    if use_cache:
        to_store = [rec for rec in combined.values() if window_start <= rec["t"] <= now]
        save_cache(args.cache, to_store)
        # After any run we've fully covered [window_start, now]: events older than
        # window_start are pruned, and we fetched/reused everything newer. Record
        # that so the next run can fetch only the delta.
        save_cache_meta(args.cache, window_start, now)
        reused = max(0, seen - len(fetched))
        print(f"  [cache] wrote {len(to_store)} events to {args.cache} "
              f"(~{reused} reused, {len(fetched)} freshly fetched)", file=sys.stderr, flush=True)

    print(f"Queried {len(user_group)} users across {len(scan_regions)} region(s) · {matched} student events aggregated", file=sys.stderr)

    # Timing breakdown: total fetch wall-clock, summed per-query time (parallelism
    # = sum/wall), and the slowest queries. If the slowest few dominate, it's a
    # heavy-hitter user; if every query is uniformly slow, it's CloudTrail's
    # per-page filtered-lookup latency / throttling — neither is fixable in code,
    # only by switching off LookupEvents (Lake/Athena).
    if timings:
        per_query_sum = sum(t[0] for t in timings)
        speedup = per_query_sum / fetch_wall if fetch_wall else 1.0
        print(f"  [timing] fetch wall {fetch_wall:.1f}s · summed query time {per_query_sum:.1f}s "
              f"· effective parallelism {speedup:.1f}x · {len(tasks)} queries", file=sys.stderr)
        slow = sorted(timings, reverse=True)[:5]
        print("  [timing] slowest queries (elapsed · region · user · pages · events):", file=sys.stderr)
        for elapsed, r, u, p, e in slow:
            print(f"             {elapsed:6.1f}s · {r} · {u} · {p} page(s) · {e} event(s)", file=sys.stderr)

    # build output users (include never-active students too)
    users = []
    for uname, gid in sorted(user_group.items()):
        a = accs.get(uname)
        if a is None:
            users.append({
                "user": uname, "group": gid,
                "total_calls": 0, "error_calls": 0, "denied_calls": 0,
                "last_active": None, "first_active": None,
                "top_service": "-", "top_event": "-",
                "services": {}, "regions": {},
                "access": {"console": 0, "terraform": 0, "sdk": 0, "other": 0},
                "daily": [0] * args.days, "denials": [], "costly": {},
                "running_resources": 0, "stuck_resources": 0,
            })
            continue
        top_service = max(a["services"].items(), key=lambda x: x[1])[0] if a["services"] else "-"
        top_event = max(a["events"].items(), key=lambda x: x[1])[0] if a["events"] else "-"
        denials = sorted(
            ({"action": k, "count": v} for k, v in a["denials"].items()),
            key=lambda x: x["count"], reverse=True,
        )
        users.append({
            "user": uname, "group": gid,
            "total_calls": a["total_calls"],
            "error_calls": a["error_calls"],
            "denied_calls": a["denied_calls"],
            "last_active": a["last_active"].strftime("%Y-%m-%dT%H:%M:%SZ") if a["last_active"] else None,
            "first_active": a["first_active"].strftime("%Y-%m-%dT%H:%M:%SZ") if a["first_active"] else None,
            "top_service": top_service, "top_event": top_event,
            "services": dict(a["services"]),
            "regions": dict(a["regions"]),
            "access": a["access"],
            "daily": a["daily"],
            "denials": denials,
            "costly": dict(a["costly"]),
            # CloudTrail can't see *current* state. A future describe/Config-based
            # collector should fill these for an accurate kill-list.
            "running_resources": 0,
            "stuck_resources": 0,
        })

    groups_meta = [
        {"id": g, "label": g, "color": GROUP_COLORS[i % len(GROUP_COLORS)],
         "home_region": group_home[g]}
        for i, g in enumerate(args.groups)
    ]

    return {
        "meta": {
            "cohort": args.cohort,
            "account_id": account_id,
            "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window_days": args.days,
            "writes_only": args.writes_only,
            "groups": groups_meta,
            "costly_weights": COSTLY_WEIGHTS,
            "heatmap": heatmap,
        },
        "users": users,
    }


def main():
    p = argparse.ArgumentParser(description="Build data.json from CloudTrail for the cohort dashboard.")
    p.add_argument("--groups", nargs="+", required=True, help="IAM group names (space separated, in display order).")
    p.add_argument("--home-regions", nargs="+", default=None,
                   help="Home region per group, parallel to --groups (e.g. ap-southeast-1 us-east-1).")
    p.add_argument("--scan-regions", nargs="+", default=None,
                   help="Extra regions to query CloudTrail in, beyond the home regions (catches sprawl).")
    p.add_argument("--days", type=int, default=30, help="Lookback window in days (CloudTrail max 90).")
    p.add_argument("--max-workers", type=int, default=8,
                   help="Parallel CloudTrail queries (default 8). Higher = faster but more throttling; "
                        "boto3 adaptive retries absorb it. Try 4 if you hit rate limits.")
    p.add_argument("--region", default=None, help="Default AWS region for IAM/STS (defaults to profile/role region).")
    p.add_argument("--profile", default=None, help="AWS profile name (omit to use ambient/instance creds).")
    p.add_argument("--cohort", default="Cohort Activity", help="Label shown in the header.")
    p.add_argument("--writes-only", action="store_true",
                   help="Count only mutating events (readOnly=false) — what students actually "
                        "create/change/delete; drops read-only describes/lists/gets.")
    p.add_argument("--cache", default=None,
                   help="Incremental event cache path (JSONL). When set, only events newer than the "
                        "last run's watermark are fetched and the rest reused — big speedup on re-runs. "
                        "Holds raw student events: keep it gitignored.")
    p.add_argument("--no-cache", action="store_true",
                   help="Ignore the --cache file for this run and force a full fetch (still rewrites it).")
    p.add_argument("--cache-overlap-min", type=int, default=20,
                   help="Re-fetch this many minutes before the cache watermark to cover CloudTrail "
                        "ingestion lag (default 20). Dedup by eventID makes the overlap harmless.")
    p.add_argument("--out", default="data.json", help="Output path.")
    args = p.parse_args()

    if args.days > 90:
        print("CloudTrail LookupEvents only covers ~90 days; capping to 90.", file=sys.stderr)
        args.days = 90

    data = collect(args)
    with open(args.out, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Wrote {args.out}: {len(data['users'])} principals", file=sys.stderr)


if __name__ == "__main__":
    main()
