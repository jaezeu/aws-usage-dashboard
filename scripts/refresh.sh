#!/usr/bin/env bash
# refresh.sh — collect CloudTrail data for the cohort dashboard, then serve it.
#
# Pass the IAM groups (and their home regions) at runtime — nothing is hardcoded:
#   ./refresh.sh --groups group-a group-b \
#                --home-regions ap-southeast-1 us-east-1 \
#                --cohort "My Cohort" \
#                --profile my-sso-profile
#
# Every flag EXCEPT --port is forwarded verbatim to collect.py:
#   --groups G1 G2 ...        IAM group names, in display order        (required)
#   --home-regions R1 R2 ...  home region per group (same order)
#   --days N                  rolling window in days (default 30, max 90)
#   --cohort "Label"          header label shown in the dashboard
#   --profile NAME            AWS profile (omit to use ambient/instance creds)
#   --scan-regions R1 R2 ...  extra regions to scan for sprawl
#   --port N                  local server port (default 8800; consumed here)
#
# Window defaults to 30 days — run this once a month. Because CloudTrail
# LookupEvents is per-region, collect.py scans every group's home region and
# merges; calls outside a group's home region show as off-region (sprawl).
set -euo pipefail

# Print the header comment block (everything after the shebang up to the first
# non-comment line) as help text.
usage() { awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; }

# This script lives in scripts/, but the dashboard HTML and the data.json it
# fetches ('./data.json') live in the repo ROOT. Collect into the root and serve
# the root — serving scripts/ would 404 the HTML and hide the data.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PORT=8800
PASS=()                                  # forwarded to collect.py
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:?--port needs a value}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) PASS+=("$1"); shift ;;
  esac
done

# --groups is required (collect.py enforces it too, but fail early with help).
case " ${PASS[*]:-} " in
  *" --groups "*) ;;
  *) echo "ERROR: --groups is required, e.g. --groups group-a group-b" >&2; echo >&2; usage >&2; exit 1 ;;
esac

# Enable the incremental event cache by default (re-runs only fetch the delta).
# Skip if the caller already chose --cache or opted out with --no-cache. The
# cache holds raw student events, so it's gitignored alongside data.json.
case " ${PASS[*]:-} " in
  *" --cache "*|*" --no-cache "*) ;;
  *) PASS+=(--cache "$ROOT_DIR/.ct-cache.jsonl") ;;
esac

echo "==> Collecting CloudTrail data into $ROOT_DIR/data.json ..."
python3 "$SCRIPT_DIR/collect.py" --out "$ROOT_DIR/data.json" "${PASS[@]}"

echo "==> data.json refreshed."
echo "==> Serving at http://localhost:${PORT}/cloudtrail-cohort-dashboard.html"
echo "    (Ctrl-C to stop. Re-run to refresh data.)"
cd "$ROOT_DIR"
python3 -m http.server "$PORT"
