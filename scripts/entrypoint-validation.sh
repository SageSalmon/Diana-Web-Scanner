#!/usr/bin/env bash
# Entrypoint for the Validation Agent ECS task.
#
# Expects env vars:
#   RUN_ID              — unique identifier for this iteration
#   BRANCH_REF          — git branch to test (informational, image is pre-built)
#   TARGET_URL          — Juice Shop URL (default: http://localhost:3000)
#   S3_ARTIFACTS_BUCKET — bucket for results
#   DATABASE_URL        — PostgreSQL connection string
#
# Outputs:
#   s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/validation/results.json

set -euo pipefail

# Env-selected entrypoint shim: ECS run-task can override `environment` but not
# `entryPoint`, so to reuse this task definition (and its Juice Shop sidecar, DB,
# and Bedrock wiring) to launch a different agent — e.g. the tiny loop — set
# AGENT_ENTRYPOINT to that script. Unset = normal validation behavior.
if [ -n "${AGENT_ENTRYPOINT:-}" ] && [ "${AGENT_ENTRYPOINT}" != "${BASH_SOURCE[0]}" ]; then
  exec /bin/bash "${AGENT_ENTRYPOINT}" "$@"
fi

RUN_ID="${RUN_ID:?RUN_ID is required}"
BRANCH_REF="${BRANCH_REF:-main}"
TARGET_URL="${TARGET_URL:-http://localhost:3000}"
S3_ARTIFACTS_BUCKET="${S3_ARTIFACTS_BUCKET:?S3_ARTIFACTS_BUCKET is required}"

export RESULTS_DIR="/tmp/agent-results"
mkdir -p "$RESULTS_DIR"

# Resolve git SHA from the image (baked in at build time)
export GIT_SHA="${GIT_SHA:-unknown}"
export IMAGE_TAG="${IMAGE_TAG:-unknown}"

echo "=== Diana Validation Agent ==="
echo "Run ID:    $RUN_ID"
echo "Branch:    $BRANCH_REF"
echo "Target:    $TARGET_URL"
echo "Artifacts: s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/validation/"
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

# --- Reset Juice Shop challenge state ---
echo "Resetting Juice Shop challenge state..."
# The Juice Shop API allows resetting via a restart; since it's a sidecar
# that just started, the state should already be clean. Verify:
SOLVED_COUNT=$(curl -sf "$TARGET_URL/api/Challenges" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(sum(1 for c in data.get('data', []) if c.get('solved')))
" 2>/dev/null || echo "0")
echo "Pre-scan solved challenges: $SOLVED_COUNT"

# --- Capture challenge baseline ---
curl -sf "$TARGET_URL/api/Challenges" > "$RESULTS_DIR/challenges-before.json"
TOTAL_CHALLENGES=$(python3 -c "
import json
data = json.load(open('$RESULTS_DIR/challenges-before.json'))
print(len(data.get('data', [])))
")
echo "Total Juice Shop challenges: $TOTAL_CHALLENGES"

# --- Run Diana scan ---
echo ""
echo "Starting Diana scan..."
SCAN_START=$(date +%s)

python -m diana.cli scan "$TARGET_URL" \
  -e engagements/local-juiceshop.yaml \
  --local \
  --modules headers,info_disclosure,xss,sqli,ssrf,auth,discovery,access_control,input_validation \
  -d 3 -r 20 \
  -f json \
  -o "$RESULTS_DIR/" \
  --verbose 2>&1 | tee "$RESULTS_DIR/scan-output.log"

SCAN_END=$(date +%s)
export SCAN_DURATION=$((SCAN_END - SCAN_START))
echo ""
echo "Scan completed in ${SCAN_DURATION}s"

# --- Capture challenge results ---
curl -sf "$TARGET_URL/api/Challenges" > "$RESULTS_DIR/challenges-after.json"

# --- Build structured results ---
python3 << 'PYTHON'
import json
import glob
import os

results_dir = os.environ["RESULTS_DIR"]
run_id = os.environ["RUN_ID"]
branch = os.environ["BRANCH_REF"]
duration = int(os.environ.get("SCAN_DURATION", "0"))

# Parse challenge state
with open(f"{results_dir}/challenges-after.json") as f:
    challenges_data = json.load(f)

challenges = challenges_data.get("data", [])
total = len(challenges)
solved = [c for c in challenges if c.get("solved")]
solved_count = len(solved)

# Per-category breakdown
by_category = {}
for c in challenges:
    cat = c.get("category", "Unknown")
    if cat not in by_category:
        by_category[cat] = {"total": 0, "solved": 0, "challenges": []}
    by_category[cat]["total"] += 1
    by_category[cat]["challenges"].append({
        "name": c.get("name"),
        "difficulty": c.get("difficulty"),
        "solved": c.get("solved", False),
    })
    if c.get("solved"):
        by_category[cat]["solved"] += 1

# Find Diana report
report_files = glob.glob(f"{results_dir}/*.json")
report_files = [f for f in report_files if "challenges" not in f and "results.json" not in f]
diana_findings = []
token_usage = {}
if report_files:
    with open(report_files[0]) as f:
        report = json.load(f)
    diana_findings = report.get("findings", [])
    token_usage = report.get("token_usage", {})

# Build output
output = {
    "run_id": run_id,
    "branch": branch,
    "agent": "validation",
    "detection": {
        "challenges_total": total,
        "challenges_solved": solved_count,
        "solve_rate": round(solved_count / total, 4) if total > 0 else 0,
        "solved_challenges": [
            {"name": c["name"], "category": c.get("category"), "difficulty": c.get("difficulty")}
            for c in solved
        ],
    },
    "findings": {
        "total": len(diana_findings),
        "by_severity": {},
    },
    "performance": {
        "scan_duration_seconds": duration,
    },
    "token_usage": token_usage,
    "categories": by_category,
}

# Count by severity
for f in diana_findings:
    sev = f.get("severity", "unknown")
    output["findings"]["by_severity"][sev] = output["findings"]["by_severity"].get(sev, 0) + 1

with open(f"{results_dir}/results.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"\nResults: {solved_count}/{total} challenges solved ({output['detection']['solve_rate']:.1%})")
print(f"Diana findings: {len(diana_findings)}")
print(f"Duration: {duration}s")
PYTHON

# --- Upload to S3 ---
echo ""
echo "Uploading results to S3..."
aws s3 cp "$RESULTS_DIR/results.json" \
  "s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/validation/results.json"
aws s3 cp "$RESULTS_DIR/scan-output.log" \
  "s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/validation/scan-output.log"

echo "Done. Results at s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/validation/results.json"
