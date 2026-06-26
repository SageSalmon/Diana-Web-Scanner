#!/usr/bin/env bash
# Entrypoint for the Tiny-Loop Agent ECS task.
#
# A lean inner-loop iteration: instead of a full crawl + every module, it reuses
# a cached sitemap (skipping the expensive crawl) and runs only the module(s)
# under test, then asserts against the Juice Shop scoreboard. Runs in the same
# sandbox as the Validation Agent (launched by reusing its task definition with
# AGENT_ENTRYPOINT set to this script).
#
# Only valid when the change under test does NOT touch the crawler — a stale
# cache would otherwise mask crawler regressions. The launching skill enforces
# that guard.
#
# Expects env vars:
#   RUN_ID              — unique identifier for this iteration
#   BRANCH_REF          — git branch under test (informational; image is pre-built)
#   TARGET_URL          — Juice Shop URL (default: http://localhost:3000)
#   S3_ARTIFACTS_BUCKET — bucket for results + the shared sitemap cache
#   MODULES             — comma-separated module(s) to run (default: access_control)
#   TARGET_CHALLENGES   — comma-separated challenge names to report on (optional)
#   SITEMAP_CACHE_KEY   — S3 key for the cached sitemap
#                         (default: cache/juiceshop-sitemap.json)
#
# Outputs:
#   s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/tinyloop/results.json
#   s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/tinyloop/scan-output.log
#   s3://$S3_ARTIFACTS_BUCKET/$SITEMAP_CACHE_KEY   (seeded on first run)

set -euo pipefail

RUN_ID="${RUN_ID:?RUN_ID is required}"
BRANCH_REF="${BRANCH_REF:-main}"
TARGET_URL="${TARGET_URL:-http://localhost:3000}"
S3_ARTIFACTS_BUCKET="${S3_ARTIFACTS_BUCKET:?S3_ARTIFACTS_BUCKET is required}"
MODULES="${MODULES:-access_control}"
TARGET_CHALLENGES="${TARGET_CHALLENGES:-}"
SITEMAP_CACHE_KEY="${SITEMAP_CACHE_KEY:-cache/juiceshop-sitemap.json}"

export RESULTS_DIR="/tmp/agent-results"
mkdir -p "$RESULTS_DIR"
SITEMAP_FILE="$RESULTS_DIR/sitemap-cache.json"

export GIT_SHA="${GIT_SHA:-unknown}"
export IMAGE_TAG="${IMAGE_TAG:-unknown}"

echo "=== Diana Tiny-Loop Agent ==="
echo "Run ID:     $RUN_ID"
echo "Branch:     $BRANCH_REF"
echo "Target:     $TARGET_URL"
echo "Modules:    $MODULES"
echo "Challenges: ${TARGET_CHALLENGES:-<all>}"
echo "Cache key:  s3://$S3_ARTIFACTS_BUCKET/$SITEMAP_CACHE_KEY"
echo "Artifacts:  s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/tinyloop/"
echo ""

# --- Wait for Juice Shop sidecar to be healthy ---
echo "Waiting for Juice Shop at $TARGET_URL ..."
RETRIES=0
MAX_RETRIES=60
until curl -sf "$TARGET_URL" > /dev/null 2>&1; do
  RETRIES=$((RETRIES + 1))
  if [ "$RETRIES" -ge "$MAX_RETRIES" ]; then
    echo "ERROR: Juice Shop did not become healthy after ${MAX_RETRIES}s"
    exit 1
  fi
  sleep 1
done
echo "Juice Shop is up."

# --- Pull the cached sitemap if it exists (else this run seeds it) ---
SEEDED_CACHE=false
if aws s3 ls "s3://$S3_ARTIFACTS_BUCKET/$SITEMAP_CACHE_KEY" > /dev/null 2>&1; then
  echo "Pulling cached sitemap ..."
  aws s3 cp "s3://$S3_ARTIFACTS_BUCKET/$SITEMAP_CACHE_KEY" "$SITEMAP_FILE"
  echo "  Cached sitemap pulled — crawl will be skipped."
else
  echo "No cached sitemap found — this run will crawl once and seed the cache."
  SEEDED_CACHE=true
fi

# --- Capture challenge baseline ---
curl -sf "$TARGET_URL/api/Challenges" > "$RESULTS_DIR/challenges-before.json"

# --- Run Diana scan (only the module(s) under test, cached crawl) ---
echo ""
echo "Starting tiny-loop scan ..."
SCAN_START=$(date +%s)

python -m diana.cli scan "$TARGET_URL" \
  -e engagements/local-juiceshop.yaml \
  --local \
  --modules "$MODULES" \
  --sitemap-cache "$SITEMAP_FILE" \
  -d 3 -r 20 \
  -f json \
  -o "$RESULTS_DIR/" \
  --verbose 2>&1 | tee "$RESULTS_DIR/scan-output.log"

SCAN_END=$(date +%s)
export SCAN_DURATION=$((SCAN_END - SCAN_START))
echo ""
echo "Scan completed in ${SCAN_DURATION}s"

# --- Seed the shared sitemap cache on first run ---
if [ "$SEEDED_CACHE" = true ] && [ -f "$SITEMAP_FILE" ]; then
  echo "Seeding shared sitemap cache to s3://$S3_ARTIFACTS_BUCKET/$SITEMAP_CACHE_KEY ..."
  aws s3 cp "$SITEMAP_FILE" "s3://$S3_ARTIFACTS_BUCKET/$SITEMAP_CACHE_KEY"
fi

# --- Capture challenge results ---
curl -sf "$TARGET_URL/api/Challenges" > "$RESULTS_DIR/challenges-after.json"

# --- Build compact tiny-loop results (scoreboard-focused) ---
export MODULES TARGET_CHALLENGES SEEDED_CACHE
python3 << 'PYTHON'
import json
import glob
import os

results_dir = os.environ["RESULTS_DIR"]
run_id = os.environ["RUN_ID"]
branch = os.environ["BRANCH_REF"]
duration = int(os.environ.get("SCAN_DURATION", "0"))
modules = [m.strip() for m in os.environ.get("MODULES", "").split(",") if m.strip()]
targets = [c.strip() for c in os.environ.get("TARGET_CHALLENGES", "").split(",") if c.strip()]
seeded = os.environ.get("SEEDED_CACHE", "false") == "true"

with open(f"{results_dir}/challenges-after.json") as f:
    challenges = json.load(f).get("data", [])

total = len(challenges)
solved = [c for c in challenges if c.get("solved")]

# Per-target challenge status (the point of the tiny loop: did THESE flip?)
by_name = {c.get("name"): c for c in challenges}
target_status = []
for name in targets:
    c = by_name.get(name)
    target_status.append({
        "name": name,
        "found": c is not None,
        "solved": bool(c.get("solved")) if c else False,
        "category": c.get("category") if c else None,
        "difficulty": c.get("difficulty") if c else None,
    })

# Diana findings (exclude the challenge snapshots and our own output)
report_files = [
    f for f in glob.glob(f"{results_dir}/*.json")
    if "challenges" not in f and "results.json" not in f and "sitemap-cache" not in f
]
diana_findings = []
if report_files:
    with open(report_files[0]) as f:
        diana_findings = json.load(f).get("findings", [])

output = {
    "run_id": run_id,
    "branch": branch,
    "agent": "tinyloop",
    "modules": modules,
    "seeded_cache": seeded,
    "detection": {
        "challenges_total": total,
        "challenges_solved": len(solved),
        "target_challenges": target_status,
        "target_solved": sum(1 for t in target_status if t["solved"]),
        "target_count": len(target_status),
    },
    "findings": {"total": len(diana_findings)},
    "performance": {"scan_duration_seconds": duration},
}

with open(f"{results_dir}/results.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"\nTiny-loop results:")
print(f"  Modules:           {', '.join(modules)}")
print(f"  Duration:          {duration}s")
print(f"  Findings:          {len(diana_findings)}")
print(f"  Overall solved:    {len(solved)}/{total}")
if target_status:
    hit = sum(1 for t in target_status if t["solved"])
    print(f"  Targeted solved:   {hit}/{len(target_status)}")
    for t in target_status:
        mark = "✓" if t["solved"] else ("·" if t["found"] else "?")
        print(f"    [{mark}] {t['name']}")
PYTHON

# --- Upload to S3 ---
echo ""
echo "Uploading results to S3..."
aws s3 cp "$RESULTS_DIR/results.json" \
  "s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/tinyloop/results.json"
aws s3 cp "$RESULTS_DIR/scan-output.log" \
  "s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/tinyloop/scan-output.log"

echo "Done. Results at s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/tinyloop/results.json"
