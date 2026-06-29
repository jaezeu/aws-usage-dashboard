# Cohort CloudTrail Dashboard

A static, credential-free dashboard that shows shared-account usage per IAM user,
split across two IAM groups. A small Python collector turns CloudTrail into a
`data.json` the page reads. The browser never touches AWS.

```
collect.py  --(CloudTrail LookupEvents)-->  data.json  -->  dashboard.html (static)
```

## Files
- `cloudtrail-cohort-dashboard.html` — the dashboard. Opens with seeded sample
  data so you can demo it immediately; loads real `data.json` when present.
- `scripts/collect.py` — reads CloudTrail, writes `data.json`.
- `scripts/refresh.sh` — collect + serve locally in one step. Pass groups and
  regions at runtime; nothing is hardcoded.
- `requirements.txt` — the single Python dependency (`boto3`).
- `LICENSE` — MIT.

## Run locally (WSL)
You pass the IAM groups (and their home regions) on the command line — there's no
config file to edit.

```bash
# from the repo root — boto3 is the only dependency (a venv is optional):
python3 -m venv .venv && source .venv/bin/activate    # optional but tidy
pip install -r requirements.txt

cd scripts
chmod +x refresh.sh                      # once

export AWS_PROFILE=my-sso-profile        # or use --profile below
./refresh.sh \
  --groups group-a group-b \
  --home-regions ap-southeast-1 us-east-1 \
  --cohort "My Cohort"
# …or pass the profile through instead of exporting it:
#   ./refresh.sh --groups group-a group-b --home-regions ap-southeast-1 us-east-1 --profile my-sso-profile
```

Replace `group-a group-b` with your real IAM group names and
`ap-southeast-1 us-east-1` with each group's home region (same order). Then open
`http://localhost:8800/cloudtrail-cohort-dashboard.html`.

The window is a rolling **30 days** (override with `--days N`) — run it once a
month, or any time you want fresh numbers. `refresh.sh` writes `data.json` to the
repo root next to the HTML and serves the root, so the link above always works.
First run does a full CloudTrail pull; re-runs only fetch the delta since the last
run (incremental cache, on by default), so they're far quicker.

`refresh.sh` forwards every flag except `--port` straight to `collect.py`; run
`./refresh.sh --help` for the full list. Because the groups operate in different
regions and CloudTrail `LookupEvents` is **per-region**, the collector scans every
group's home region and merges the results — otherwise one group's activity would
be invisible. Calls a student makes outside their group's home region are flagged
as **off-region** (sprawl) in the dashboard.

## Common variations
Every flag is forwarded to `collect.py` (`./refresh.sh --help` for the full list).
The ones you'll actually reach for:

| Goal | Add |
|---|---|
| Shorter/longer window | `--days 7` (max 90) |
| Count only writes (creates/changes/deletes) | `--writes-only` |
| Catch sprawl in more regions | `--scan-regions eu-west-1 us-west-2` |
| Force a full re-fetch, ignore the cache | `--no-cache` |
| Dial back parallelism if you hit throttling | `--max-workers 4` |
| Serve on a different port | `--port 9000` |

Example — last 7 days, writes only, also scanning `eu-west-1`:

```bash
./refresh.sh --groups group-a group-b --home-regions ap-southeast-1 us-east-1 \
  --days 7 --writes-only --scan-regions eu-west-1
```

> **Git safety:** `data.json` (real student usernames + activity + account ID) is
> gitignored and must not be committed. Group names are passed at runtime, so
> nothing in the repo carries them. The dashboard still renders standalone from
> its built-in sample data without `data.json`.

## What the IAM principal running the collector needs
Read-only:
- `cloudtrail:LookupEvents`
- `iam:GetGroup` (to list members of each group)
- `sts:GetCallerIdentity`

> **Why serve, not double-click?** Opening the file as `file://` blocks
> `fetch('./data.json')` (browser CORS), so it silently falls back to sample
> data. Serving over `http://` (what `refresh.sh` does) fixes it. The top-right
> pill shows which source is live: `data.json` vs `sample`.

> **Catching sprawl beyond the two home regions:** pass extra regions to scan
> with `--scan-regions eu-west-1 us-west-2 ...` if you want to detect students
> straying further afield. Anything outside a group's home region shows as
> off-region regardless; `--scan-regions` just widens where the collector looks.

## Portability — moving to AWS later
The front end needs no changes: it's just static files reading a sibling
`data.json`. Two moves and you're hosted:

1. **Host the static files.** Drop `cloudtrail-cohort-dashboard.html` and
   `data.json` in an S3 bucket behind CloudFront (private bucket + OAC, or gate
   with Cognito/Lambda@Edge since it's student data).
2. **Run the collector on a schedule.** Put `collect.py` on Lambda (or a small
   ECS/Fargate task) on an EventBridge cron, writing `data.json` to the same S3
   bucket. **No code change** — drop the `--profile` flag and it uses the
   execution role via the default credential chain. That's the whole reason the
   collector reads creds ambiently rather than hard-coding a profile.

So local and cloud run the *same* `collect.py`; only the credential source and
the `data.json` destination differ.

## Notes / limits
- `running_resources` and `stuck_resources` are `0` from CloudTrail alone — the
  trail records *actions*, not *current state*. To make the stuck-resource
  "kill list" reflect reality, add a second describe/Config-based collector that
  snapshots live resources and merges those two fields in. Left as a clean
  extension point.
- CloudTrail `LookupEvents` covers ~90 days of **management events** and is
  rate-limited, so large windows take a while. For heavier use, switch the
  collector to query a CloudTrail Lake / Athena table over the same schema.
- The collector queries CloudTrail **once per group member** with a server-side
  `Username` filter, so it only pages through the students' own events rather than
  the whole account's activity — much faster on a busy shared account. Caveat: the
  `Username` attribute matches the name CloudTrail records (the IAM user name, or
  the role-session name for assumed roles). If a student operates under an assumed
  role whose session name differs from their IAM user name, that activity won't be
  captured. Cohort IAM users calling AWS directly are matched correctly.
- Per-group **home-region scoping**: each home region only queries the users whose
  group lives there (group-a in ap-southeast-1, group-b in us-east-1), halving the
  query count. `--scan-regions` extras still query everyone (sprawl detection).
- Per-user CloudTrail queries run **in parallel** (`--max-workers`, default 8).
  `LookupEvents` is throttled at ~2 req/sec **per region**, so this is bounded by
  that quota, not linear — boto3 adaptive retries absorb throttling. The collector
  prints a `[timing]` breakdown (auth, IAM mapping, fetch wall-clock, effective
  parallelism, slowest queries) so you can see where time goes.
- **Incremental cache** (`--cache PATH`, auto-enabled by `refresh.sh`): CloudTrail
  events are immutable, so the collector persists every fetched event (keyed by
  `eventID`) and on the next run only fetches events **newer than the last run**
  (minus a 20-min overlap for ingestion lag, deduped by `eventID`). First run is
  full; re-runs fetch just the delta — a re-run minutes later is near-instant. The
  cache stores **all** events pre-`--writes-only` filter (the readOnly filter is
  applied at aggregation), so an all-events run after a writes-only one stays
  correct. Coverage is tracked in a `.meta` sidecar (not inferred from event
  times, so quiet periods are handled). Use `--no-cache` to force a full fetch.
  The cache holds raw student events — it's **gitignored** like `data.json`.
- The real ceiling is `LookupEvents` itself (per-region 2 req/sec + per-page
  filtered-lookup latency). For a step-change in speed, switch the collector to
  CloudTrail **Lake** or **Athena** (one SQL query, same `data.json` schema).
- **`--writes-only`** counts only mutating events (`readOnly=false`) — what students
  actually create, change or delete — and drops read-only describes/lists/gets.
  `LookupEvents` permits a single attribute per call (already used for `Username`),
  so reads are filtered client-side on each event's `readOnly` field. With this on,
  call counts, the IaC ratio and the timeline reflect *writes only*, and the
  dashboard header shows a `writes only` tag. Example:
  `./refresh.sh --groups group-a group-b --home-regions ap-southeast-1 us-east-1 --writes-only`
- Access-method classification is heuristic (matches `userAgent` for console /
  Terraform / SDK); tune the strings in `classify_access()` if your tooling
  reports differently.
