#!/usr/bin/env bash
# Launch an agent ECS task.
#
# Usage:
#   ./scripts/run-agent-task.sh <task-type> <branch-ref> [run-id]
#
# Arguments:
#   task-type   — validation | test | benchmark
#   branch-ref  — git branch to build and test
#   run-id      — optional; auto-generated as iteration-<timestamp> if omitted
#
# Prerequisites:
#   - AWS CLI configured with appropriate credentials
#   - Terraform outputs available (or env vars set manually):
#     AGENT_ARTIFACTS_BUCKET, CODEBUILD_PROJECT, ECS_CLUSTER, ECS_SUBNETS, ECS_SG
#
# Steps:
#   1. Trigger CodeBuild to build Diana image from branch
#   2. Wait for build to complete
#   3. Run ECS task with the built image
#   4. Print task ARN for monitoring

set -euo pipefail

TASK_TYPE="${1:?Usage: $0 <validation|test|benchmark> <branch-ref> [run-id]}"
BRANCH_REF="${2:?Usage: $0 <task-type> <branch-ref> [run-id]}"
RUN_ID="${3:-iteration-$(date +%Y%m%d-%H%M%S)}"

# --- Resolve infrastructure from Terraform outputs ---
TF_DIR="tf/environments/dev"

get_tf_output() {
  terraform -chdir="$TF_DIR" output -raw "$1" 2>/dev/null
}

ARTIFACTS_BUCKET="${AGENT_ARTIFACTS_BUCKET:-$(get_tf_output agent_artifacts_bucket)}"
CODEBUILD_PROJECT="${CODEBUILD_PROJECT:-$(get_tf_output agent_codebuild_project)}"
CLUSTER_ARN="${ECS_CLUSTER:-$(get_tf_output cluster_arn)}"
SUBNETS="${ECS_SUBNETS:-$(get_tf_output private_subnet_ids)}"
SG="${ECS_SG:-$(get_tf_output scanner_sg_id)}"

# Map task type to task definition family
case "$TASK_TYPE" in
  validation) TASK_FAMILY="diana-agent-validation"; CONTAINER_NAME="diana-scanner" ;;
  test)       TASK_FAMILY="diana-agent-test";       CONTAINER_NAME="diana-test" ;;
  benchmark)  TASK_FAMILY="diana-agent-benchmark";  CONTAINER_NAME="diana-scanner" ;;
  *)
    echo "ERROR: Unknown task type: $TASK_TYPE"
    echo "Valid types: validation, test, benchmark"
    exit 1
    ;;
esac

echo "=== Diana Agent Task Launcher ==="
echo "Task type: $TASK_TYPE"
echo "Branch:    $BRANCH_REF"
echo "Run ID:    $RUN_ID"
echo "Cluster:   $CLUSTER_ARN"
echo ""

# --- Step 1: Build image from branch ---
BRANCH_TAG=$(echo "$BRANCH_REF" | sed 's/[^a-zA-Z0-9_.-]/-/g')

echo "Step 1: Building Diana image for branch $BRANCH_REF..."
BUILD_ID=$(aws codebuild start-build \
  --project-name "$CODEBUILD_PROJECT" \
  --source-version "$BRANCH_REF" \
  --environment-variables-override "name=BRANCH_REF,value=$BRANCH_REF" \
  --query 'build.id' --output text)

echo "  CodeBuild ID: $BUILD_ID"

# --- Step 2: Wait for build ---
echo "Step 2: Waiting for build to complete..."
while true; do
  STATUS=$(aws codebuild batch-get-builds \
    --ids "$BUILD_ID" \
    --query 'builds[0].buildStatus' --output text)

  case "$STATUS" in
    SUCCEEDED)
      echo "  Build succeeded."
      break
      ;;
    FAILED|FAULT|STOPPED|TIMED_OUT)
      echo "  ERROR: Build $STATUS"
      echo "  Check logs: aws codebuild batch-get-builds --ids $BUILD_ID"
      exit 1
      ;;
    *)
      echo "  Build status: $STATUS ..."
      sleep 10
      ;;
  esac
done

# --- Step 3: Run ECS task ---
echo "Step 3: Launching ECS task ($TASK_FAMILY)..."

TASK_ARN=$(aws ecs run-task \
  --cluster "$CLUSTER_ARN" \
  --task-definition "$TASK_FAMILY" \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$SUBNETS],securityGroups=[$SG],assignPublicIp=DISABLED}" \
  --overrides "{
    \"containerOverrides\": [{
      \"name\": \"$CONTAINER_NAME\",
      \"environment\": [
        {\"name\": \"RUN_ID\", \"value\": \"$RUN_ID\"},
        {\"name\": \"BRANCH_REF\", \"value\": \"$BRANCH_REF\"}
      ]
    }]
  }" \
  --query 'tasks[0].taskArn' --output text)

echo ""
echo "=== Task launched ==="
echo "Task ARN:   $TASK_ARN"
echo "Run ID:     $RUN_ID"
echo "Results at: s3://$ARTIFACTS_BUCKET/$RUN_ID/$TASK_TYPE/results.json"
echo ""
echo "Monitor: aws ecs describe-tasks --cluster $CLUSTER_ARN --tasks $TASK_ARN --query 'tasks[0].lastStatus'"
