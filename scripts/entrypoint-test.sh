#!/usr/bin/env bash
# Entrypoint for the Test Runner Agent ECS task.
#
# Expects env vars:
#   RUN_ID              — unique identifier for this iteration
#   S3_ARTIFACTS_BUCKET — bucket for results
#
# Outputs:
#   s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/test-runner/results.json

set -euo pipefail

RUN_ID="${RUN_ID:?RUN_ID is required}"
S3_ARTIFACTS_BUCKET="${S3_ARTIFACTS_BUCKET:?S3_ARTIFACTS_BUCKET is required}"

export RESULTS_DIR="/tmp/agent-results"
mkdir -p "$RESULTS_DIR"

echo "=== Diana Test Runner Agent ==="
echo "Run ID:    $RUN_ID"
echo "Artifacts: s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/test-runner/"
echo ""

# --- Install test dependencies ---
echo "Installing test dependencies..."
pip install --no-cache-dir --user ".[dev]" -q

# --- Run pytest ---
echo "Running test suite..."
TEST_START=$(date +%s)

python -m pytest tests/ \
  --tb=short \
  --junitxml="$RESULTS_DIR/junit.xml" \
  -q 2>&1 | tee "$RESULTS_DIR/pytest-output.log"

export TEST_EXIT_CODE=${PIPESTATUS[0]}
TEST_END=$(date +%s)
export TEST_DURATION=$((TEST_END - TEST_START))

echo ""
echo "Tests completed in ${TEST_DURATION}s (exit code: $TEST_EXIT_CODE)"

# --- Build structured results ---
python3 << 'PYTHON'
import json
import os
import xml.etree.ElementTree as ET

results_dir = os.environ["RESULTS_DIR"]
run_id = os.environ["RUN_ID"]
exit_code = int(os.environ.get("TEST_EXIT_CODE", "1"))
duration = int(os.environ.get("TEST_DURATION", "0"))

# Parse JUnit XML
output = {
    "run_id": run_id,
    "agent": "test-runner",
    "passed": exit_code == 0,
    "exit_code": exit_code,
    "duration_seconds": duration,
    "tests": {"total": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0},
    "failures": [],
}

try:
    tree = ET.parse(f"{results_dir}/junit.xml")
    root = tree.getroot()

    for suite in root.iter("testsuite"):
        output["tests"]["total"] += int(suite.get("tests", 0))
        output["tests"]["failures"] = int(suite.get("failures", 0))
        output["tests"]["errors"] += int(suite.get("errors", 0))
        output["tests"]["skipped"] += int(suite.get("skipped", 0))

    output["tests"]["passed"] = (
        output["tests"]["total"]
        - output["tests"]["failures"]
        - output["tests"]["errors"]
        - output["tests"]["skipped"]
    )
    # Rename to match expected field
    output["tests"]["failed"] = output["tests"].pop("failures")

    # Capture failure details
    for testcase in root.iter("testcase"):
        failure = testcase.find("failure")
        error = testcase.find("error")
        if failure is not None or error is not None:
            elem = failure if failure is not None else error
            output["failures"].append({
                "test": f"{testcase.get('classname', '')}.{testcase.get('name', '')}",
                "message": elem.get("message", ""),
            })
except FileNotFoundError:
    output["tests"]["total"] = 0
    output["failures"].append({"test": "N/A", "message": "No junit.xml produced"})

with open(f"{results_dir}/results.json", "w") as f:
    json.dump(output, f, indent=2)

status = "PASSED" if exit_code == 0 else "FAILED"
print(f"\nTest result: {status}")
print(f"  Total: {output['tests']['total']}, Passed: {output['tests']['passed']}, Failed: {output['tests']['failed']}")
PYTHON

# --- Upload to S3 ---
echo ""
echo "Uploading results to S3..."
aws s3 cp "$RESULTS_DIR/results.json" \
  "s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/test-runner/results.json"
aws s3 cp "$RESULTS_DIR/pytest-output.log" \
  "s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/test-runner/pytest-output.log"
[ -f "$RESULTS_DIR/junit.xml" ] && aws s3 cp "$RESULTS_DIR/junit.xml" \
  "s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/test-runner/junit.xml"

echo "Done. Results at s3://$S3_ARTIFACTS_BUCKET/$RUN_ID/test-runner/results.json"
