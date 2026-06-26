#!/usr/bin/env bash
# Entrypoint for the Benchmark Agent ECS task.
#
# Expects env vars:
#   RUN_ID              — unique identifier for this iteration
#   BRANCH_REF          — git branch being benchmarked
#   TARGET_URL          — Juice Shop URL (default: http://localhost:3000)
#   S3_ARTIFACTS_BUCKET — bucket for results
#   DATABASE_URL        — PostgreSQL connection string
#
# Outputs:
#   s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/benchmark/results.json

set -euo pipefail

RUN_ID="${RUN_ID:?RUN_ID is required}"
BRANCH_REF="${BRANCH_REF:-main}"
TARGET_URL="${TARGET_URL:-http://localhost:3000}"
S3_ARTIFACTS_BUCKET="${S3_ARTIFACTS_BUCKET:?S3_ARTIFACTS_BUCKET is required}"

export RESULTS_DIR="/tmp/agent-results"
mkdir -p "$RESULTS_DIR"

echo "=== Diana Benchmark Agent ==="
echo "Run ID:    $RUN_ID"
echo "Branch:    $BRANCH_REF"
echo "Target:    $TARGET_URL"
echo "Artifacts: s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/benchmark/"
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

# --- Run Diana scan (timed) ---
echo ""
echo "Starting benchmark scan..."
SCAN_START=$(date +%s)

python -m diana.cli scan "$TARGET_URL" \
  -e engagements/local-juiceshop.yaml \
  --local \
  --modules headers,info_disclosure,xss,sqli,ssrf,auth,discovery,access_control \
  -d 3 -r 20 \
  -f json \
  -o "$RESULTS_DIR/" \
  --verbose 2>&1 | tee "$RESULTS_DIR/scan-output.log"

SCAN_END=$(date +%s)
export SCAN_DURATION=$((SCAN_END - SCAN_START))
echo ""
echo "Benchmark scan completed in ${SCAN_DURATION}s"

# --- Build structured results ---
python3 << 'PYTHON'
import json
import glob
import os

results_dir = os.environ["RESULTS_DIR"]
run_id = os.environ["RUN_ID"]
branch = os.environ["BRANCH_REF"]
duration = int(os.environ.get("SCAN_DURATION", "0"))

# Find Diana report
report_files = glob.glob(f"{results_dir}/*.json")
report_files = [f for f in report_files if "results.json" not in f]
diana_report = {}
if report_files:
    with open(report_files[0]) as f:
        diana_report = json.load(f)

token_usage = diana_report.get("token_usage", {})
findings = diana_report.get("findings", [])

# Calculate token totals
total_input = sum(m.get("input_tokens", 0) for m in token_usage.values()) if isinstance(token_usage, dict) else 0
total_output = sum(m.get("output_tokens", 0) for m in token_usage.values()) if isinstance(token_usage, dict) else 0
total_calls = sum(m.get("calls", 0) for m in token_usage.values()) if isinstance(token_usage, dict) else 0

# Count HTTP requests from log (approximate from scan output)
http_requests = 0
try:
    with open(f"{results_dir}/scan-output.log") as f:
        for line in f:
            if "HTTP" in line and ("GET" in line or "POST" in line or "PUT" in line):
                http_requests += 1
except FileNotFoundError:
    pass

output = {
    "run_id": run_id,
    "branch": branch,
    "agent": "benchmark",
    "performance": {
        "scan_duration_seconds": duration,
        "http_requests": http_requests,
        "findings_count": len(findings),
    },
    "tokens": {
        "total_input": total_input,
        "total_output": total_output,
        "total_calls": total_calls,
        "by_module": token_usage,
    },
}

with open(f"{results_dir}/results.json", "w") as f:
    json.dump(output, f, indent=2)

print(f"\nBenchmark results:")
print(f"  Duration:      {duration}s")
print(f"  Findings:      {len(findings)}")
print(f"  Input tokens:  {total_input:,}")
print(f"  Output tokens: {total_output:,}")
print(f"  LLM calls:     {total_calls}")
PYTHON

# --- Upload to S3 ---
echo ""
echo "Uploading results to S3..."
aws s3 cp "$RESULTS_DIR/results.json" \
  "s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/benchmark/results.json"
aws s3 cp "$RESULTS_DIR/scan-output.log" \
  "s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/benchmark/scan-output.log"

echo "Done. Results at s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/benchmark/results.json"
