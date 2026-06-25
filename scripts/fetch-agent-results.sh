#!/usr/bin/env bash
# Fetch agent results from S3.
#
# Usage:
#   ./scripts/fetch-agent-results.sh <run-id> [agent-name]
#
# Arguments:
#   run-id      — iteration identifier
#   agent-name  — optional: validation | test-runner | benchmark
#                 If omitted, fetches all agents for the run.
#
# Output:
#   Downloads to ./agent-results/<run-id>/<agent>/

set -euo pipefail

RUN_ID="${1:?Usage: $0 <run-id> [agent-name]}"
AGENT_NAME="${2:-}"

# Resolve bucket from Terraform
TF_DIR="tf/environments/dev"
ARTIFACTS_BUCKET="${AGENT_ARTIFACTS_BUCKET:-$(terraform -chdir="$TF_DIR" output -raw agent_artifacts_bucket 2>/dev/null)}"

LOCAL_DIR="./agent-results/$RUN_ID"
mkdir -p "$LOCAL_DIR"

if [ -n "$AGENT_NAME" ]; then
  echo "Fetching $AGENT_NAME results for run $RUN_ID..."
  mkdir -p "$LOCAL_DIR/$AGENT_NAME"
  aws s3 cp --recursive \
    "s3://$ARTIFACTS_BUCKET/$RUN_ID/$AGENT_NAME/" \
    "$LOCAL_DIR/$AGENT_NAME/"
else
  echo "Fetching all agent results for run $RUN_ID..."
  aws s3 cp --recursive \
    "s3://$ARTIFACTS_BUCKET/$RUN_ID/" \
    "$LOCAL_DIR/"
fi

echo ""
echo "Results downloaded to $LOCAL_DIR/"
echo ""

# Print summary if results.json files exist
for results_file in "$LOCAL_DIR"/*/results.json; do
  [ -f "$results_file" ] || continue
  agent=$(basename "$(dirname "$results_file")")
  echo "--- $agent ---"
  python3 -c "
import json
with open('$results_file') as f:
    data = json.load(f)

agent = data.get('agent', '$agent')
if agent == 'validation':
    det = data.get('detection', {})
    print(f\"  Solve rate: {det.get('challenges_solved', 0)}/{det.get('challenges_total', 0)} ({det.get('solve_rate', 0):.1%})\")
    print(f\"  Findings: {data.get('findings', {}).get('total', 0)}\")
    print(f\"  Duration: {data.get('performance', {}).get('scan_duration_seconds', 0)}s\")
elif agent == 'test-runner':
    tests = data.get('tests', {})
    status = 'PASSED' if data.get('passed') else 'FAILED'
    print(f\"  Status: {status}\")
    print(f\"  Tests: {tests.get('total', 0)} total, {tests.get('passed', 0)} passed, {tests.get('failed', 0)} failed\")
elif agent == 'benchmark':
    perf = data.get('performance', {})
    tokens = data.get('tokens', {})
    print(f\"  Duration: {perf.get('scan_duration_seconds', 0)}s\")
    print(f\"  Input tokens: {tokens.get('total_input', 0):,}\")
    print(f\"  Output tokens: {tokens.get('total_output', 0):,}\")
    print(f\"  LLM calls: {tokens.get('total_calls', 0)}\")
elif agent == 'tinyloop':
    det = data.get('detection', {})
    print(f\"  Modules: {', '.join(data.get('modules', []))}\")
    print(f\"  Targeted solved: {det.get('target_solved', 0)}/{det.get('target_count', 0)}\")
    print(f\"  Overall solved: {det.get('challenges_solved', 0)}/{det.get('challenges_total', 0)}\")
    print(f\"  Duration: {data.get('performance', {}).get('scan_duration_seconds', 0)}s\")
    for t in det.get('target_challenges', []):
        mark = 'x' if t.get('solved') else ('.' if t.get('found') else '?')
        print(f\"    [{mark}] {t.get('name')}\")
" 2>/dev/null || echo "  (could not parse results)"
  echo ""
done
