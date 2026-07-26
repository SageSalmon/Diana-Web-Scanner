export const meta = {
  name: 'juiceshop-solve-loop',
  description: 'Autonomous parallel-auditor loop: improve N scanner modules per round, validate each in its own AWS sandbox, integrate, full-scan, auto-merge — until a Juice Shop solve-rate % target is hit.',
  whenToUse: 'When you want to drive Diana toward a solve-rate % target hands-off. Fully autonomous: writes generic scanner code, gates it, tiny-loops in parallel, and self-merges improvements that raise the score with zero regressions. Needs AWS infra already up.',
  phases: [
    { title: 'Prep', detail: 'verify infra + read baseline solve count' },
    { title: 'Plan', detail: 'pick N module-disjoint opportunities from the gap analysis' },
    { title: 'Improve', detail: 'one Opus agent per auditor writes generic code (worktree-isolated)', model: 'opus' },
    { title: 'Gates', detail: 'generality + test-author + test-critic per branch' },
    { title: 'Tinyloop', detail: 'parallel single-module scans, each on its own Juice Shop sidecar' },
    { title: 'Integrate', detail: 'merge the green branches' },
    { title: 'Smoke', detail: 'fast single-module scan of the integration image — fail fast on crashers before the 105-min full scan' },
    { title: 'BigScan', detail: 'one full validation; auto-merge to main if score rose with no regressions' },
    { title: 'Teardown', detail: 'terraform destroy the AWS sandbox at the end of the run' },
  ],
}

// ---- Inputs (args) ---------------------------------------------------------
// args = { targetPct, auditorsPerRound?, maxRounds?, modules?, dryRoundLimit? }
// Normalize: args may arrive as an object, or as a JSON-encoded string. Coerce
// numerics with Number() so a string like "22" is accepted.
let A = args
if (typeof A === 'string') { try { A = JSON.parse(A) } catch (e) { A = {} } }
A = A || {}
const numArg = (v) => (v != null && v !== '' && !isNaN(Number(v))) ? Number(v) : null

const TARGET_PCT = numArg(A.targetPct)
if (TARGET_PCT === null) {
  throw new Error('juiceshop-solve-loop requires args.targetPct (e.g. { targetPct: 22 }). Refusing to run without a target.')
}
const AUDITORS = numArg(A.auditorsPerRound) || 3
// One workflow run executes up to MAX_ROUNDS rounds, stopping early only when the
// absolute % target is reached (or the token budget runs low). Improving rounds
// direct-auto-merge to main and the loop continues on the fresh state; the
// per-round checkin is the CHRONICLE update + log line (watch /workflows live).
const MAX_ROUNDS = numArg(A.maxRounds) || 5
// A no-gain round does NOT stop the run — it tries fresh opportunities next round
// up to the round cap. Default disables the dry early-stop; pass dryRoundLimit:N
// to opt into stopping after N consecutive no-gain rounds.
const DRY_LIMIT = numArg(A.dryRoundLimit) || MAX_ROUNDS
// Tear the AWS sandbox down when the run finishes (default on). Pass
// teardown:false to leave infra up (e.g. to inspect results or chain runs).
const TEARDOWN = !(A.teardown === false)
const MODULE_HINT = A.modules || null                        // optional explicit module list
const TOTAL = 113
const CRAWLER_SET = ['src/diana/core/crawler.py', 'src/diana/core/spa_crawler.py', 'src/diana/core/models.py']

const pct = (n) => Math.round((n / TOTAL) * 1000) / 10

// ---- Structured-output schemas --------------------------------------------
const PREP_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['infra_up', 'baseline_solved', 'solved_challenges', 'artifacts_bucket', 'notes'],
  properties: {
    infra_up: { type: 'boolean', description: 'true only if terraform outputs resolve AND the ECS cluster + CodeBuild project exist' },
    baseline_solved: { type: 'integer', description: 'most recent known solved-challenge count (from newest agent-results/*/validation/results.json, else the chronicle baseline)' },
    solved_challenges: { type: 'array', items: { type: 'string' }, description: 'the exact NAMES of challenges already solved at baseline (detection.solved_challenges), so the planner can avoid re-targeting them. Empty array if unknown.' },
    artifacts_bucket: { type: 'string' },
    notes: { type: 'string' },
  },
}
const PLAN_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['opportunities'],
  properties: {
    opportunities: {
      type: 'array', maxItems: 8,
      items: {
        type: 'object', additionalProperties: false,
        required: ['module', 'title', 'target_challenges', 'rationale'],
        properties: {
          module: { type: 'string', description: 'the single scanner module this auditor will change (e.g. xss, access_control, sensitive_data_exposure). Must be module-disjoint from the others.' },
          title: { type: 'string' },
          target_challenges: { type: 'array', items: { type: 'string' }, description: 'Juice Shop challenge names this change should flip' },
          rationale: { type: 'string' },
        },
      },
    },
  },
}
const IMPROVE_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['ok', 'branch', 'touched_crawler', 'files_changed', 'summary'],
  properties: {
    ok: { type: 'boolean', description: 'true if a focused, committed, pushed generic improvement was produced' },
    branch: { type: 'string' },
    touched_crawler: { type: 'boolean', description: 'true if the diff touches crawler.py, spa_crawler.py, or models.py (disqualifies the tiny-loop)' },
    files_changed: { type: 'array', items: { type: 'string' } },
    summary: { type: 'string' },
  },
}
const GATE_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['verdict', 'detail'],
  properties: {
    verdict: { type: 'string', enum: ['PASS', 'WARN', 'FAIL'] },
    detail: { type: 'string' },
  },
}
const TINYLOOP_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['flipped', 'flipped_challenges', 'net_new_challenges', 'detail'],
  properties: {
    flipped: { type: 'boolean', description: 'true ONLY if at least one NET-NEW challenge (not in the provided already-solved list) went unsolved -> solved. Re-solving an already-solved challenge does NOT count.' },
    flipped_challenges: { type: 'array', items: { type: 'string' }, description: 'all target challenges that went 0->solved in this fresh sidecar' },
    net_new_challenges: { type: 'array', items: { type: 'string' }, description: 'the subset of flipped_challenges that are NOT already in the baseline solved list' },
    detail: { type: 'string' },
  },
}
const SMOKE_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['healthy', 'detail'],
  properties: {
    healthy: { type: 'boolean', description: 'true if the scan ran to completion without a crash/exception (AI payload generation, orchestrator, etc.). Flips are irrelevant here — this only checks the integrated image does not crash.' },
    detail: { type: 'string' },
  },
}
const INTEGRATE_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['ok', 'branch', 'merged_branches', 'detail'],
  properties: {
    ok: { type: 'boolean' },
    branch: { type: 'string' },
    merged_branches: { type: 'array', items: { type: 'string' } },
    detail: { type: 'string' },
  },
}
const BIGSCAN_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['solved', 'solved_challenges', 'duration_s', 'detail'],
  properties: {
    solved: { type: 'integer', description: 'challenges_solved from the full validation results.json; use -1 if the scan crashed/produced no results (so the round is treated as no-merge, not a regression to 0)' },
    solved_challenges: { type: 'array', items: { type: 'string' }, description: 'the EXACT names of every challenge solved in this scan (detection.solved_challenges verbatim). The workflow computes newly-solved and regressions from this — do not pre-diff it.' },
    duration_s: { type: 'number' },
    detail: { type: 'string' },
  },
}
const MERGE_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['merged', 'detail'],
  properties: { merged: { type: 'boolean' }, detail: { type: 'string' } },
}
const TEARDOWN_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['ok', 'detail'],
  properties: { ok: { type: 'boolean' }, detail: { type: 'string' } },
}

// ---- One auditor: improve -> gates -> tiny-loop ----------------------------
async function runAuditor(pick, round, solvedNames) {
  const branch = `auto/${pick.module}-r${round}`
  const label = `${pick.module}:r${round}`
  const solvedSet = new Set((solvedNames || []).map(s => (s || '').toLowerCase()))

  const imp = await agent(
    `You are the Improvement Agent. Follow .claude/skills/agent-improvement/SKILL.md.
Implement ONE focused, GENERIC improvement to the "${pick.module}" scanner module only, to flip: ${pick.target_challenges.join(', ')}.
Rationale: ${pick.rationale}
Rules: stay inside the "${pick.module}" module's files; do NOT touch ${CRAWLER_SET.join(', ')} (that disqualifies the fast tiny-loop). No target-specific code, hostnames, challenge names, or credentials in control flow. Create branch "${branch}" from latest main (delete/reset it first if it already exists), commit, and push it to origin (CodeBuild builds from the remote branch).
Return the branch, whether the diff touched the crawler set (git diff --name-only main...${branch}), and the files changed.`,
    { label: `improve:${label}`, phase: 'Improve', model: 'opus', isolation: 'worktree', schema: IMPROVE_SCHEMA },
  )
  if (!imp || !imp.ok) return { ...pick, branch, flipped: false, reason: 'no-improvement' }
  if (imp.touched_crawler) return { ...pick, branch, flipped: false, reason: 'touched-crawler (needs full-scan round, not tiny-loop)' }

  const gen = await agent(
    `Review the diff on branch ${branch} (git diff main...${branch}) for target-specific patterns. Reject anything that only works against Juice Shop and would not help scan a Django/Spring/Rails app. Report verdict PASS/WARN/FAIL.`,
    { label: `generality:${label}`, phase: 'Gates', agentType: 'agent-generality', schema: GATE_SCHEMA },
  )
  if (!gen || gen.verdict === 'FAIL') return { ...pick, branch, flipped: false, reason: 'generality-fail' }

  await agent(
    `Write generic unit/integration tests for the scanner change on branch ${branch} (synthetic fixtures, neutral URLs). Commit and push to ${branch}.`,
    { label: `test-author:${label}`, phase: 'Gates', agentType: 'agent-test-author' },
  )
  let critic = await agent(
    `Review the tests added on branch ${branch} for correctness, completeness, and independence. Reject vacuous/tautological/target-specific tests. Report PASS or FAIL with specifics.`,
    { label: `test-critic:${label}`, phase: 'Gates', agentType: 'agent-test-critic', schema: GATE_SCHEMA },
  )
  if (critic && critic.verdict === 'FAIL') {
    // one repair attempt
    await agent(
      `The Test Critic rejected the tests on branch ${branch}: ${critic.detail}. Fix or replace the tests at the root (do not loosen assertions). Commit and push to ${branch}.`,
      { label: `test-fix:${label}`, phase: 'Gates', agentType: 'agent-test-author' },
    )
    critic = await agent(
      `Re-review (attempt 2) the tests on branch ${branch} after the author's fix. Report PASS or FAIL.`,
      { label: `test-critic2:${label}`, phase: 'Gates', agentType: 'agent-test-critic', schema: GATE_SCHEMA },
    )
    if (critic && critic.verdict === 'FAIL') return { ...pick, branch, flipped: false, reason: 'test-critic-fail' }
  }

  const tl = await agent(
    `Follow .claude/skills/agent-tinyloop/SKILL.md for branch ${branch}, MODULES="${pick.module}", TARGET_CHALLENGES="${pick.target_challenges.join(',')}".
First confirm the tiny-loop guard (diff must not touch the crawler set). Build from the remote branch, run the single-module scan against its own Juice Shop sidecar reusing a cached crawl, and report which target challenges flipped unsolved->solved.

IMPORTANT — net-new only: the sidecar starts at 0 solved, so a challenge that is ALREADY solved on main will also flip 0->solved here and must NOT be counted as a win. These challenges are already solved at baseline and DO NOT count as net-new: [${(solvedNames || []).join(', ') || 'none'}]. Report net_new_challenges = the flipped challenges NOT in that list, and set flipped=true ONLY if net_new_challenges is non-empty.

IMPORTANT — no orphaned tasks: if you launch an ECS task, you MUST wait for it to reach a terminal state; if you give up or time out, STOP the task ('aws ecs stop-task --cluster diana-cluster --task <arn>') before returning so it does not keep running and billing.`,
    { label: `tinyloop:${label}`, phase: 'Tinyloop', agentType: 'agent-tinyloop', schema: TINYLOOP_SCHEMA },
  )
  // Belt-and-suspenders: compute net-new here too, don't trust the flag alone.
  const flippedCh = (tl && tl.flipped_challenges) || []
  const netNew = ((tl && tl.net_new_challenges) || flippedCh).filter(c => !solvedSet.has((c || '').toLowerCase()))
  const isWin = !!(tl && tl.flipped) && netNew.length > 0
  return {
    ...pick, branch,
    flipped: isWin,
    flipped_challenges: flippedCh,
    net_new_challenges: netNew,
    reason: isWin ? `net-new: ${netNew.join(', ')}` : (flippedCh.length ? 'only-already-solved' : 'no-flip'),
  }
}

// ---- Main loop -------------------------------------------------------------
phase('Prep')
const prep = await agent(
  `You are prepping an autonomous scanner-improvement loop.
1. Verify AWS infra is UP: \`terraform -chdir=tf/environments/dev output -raw agent_artifacts_bucket\` resolves, the ECS cluster "diana-cluster" exists, and the CodeBuild project "diana-agent-build" exists. Set infra_up accordingly.
2. Determine the current baseline. The AUTHORITATIVE current solve count is the TOP (most recent) "## Round N" / "## Iteration N" entry in docs/CHRONICLE.md — it is updated on every merge, so trust it over any results.json (local result files may be stale or partial). Parse its "X/113" solved count and return it as baseline_solved.
3. For solved_challenges NAMES, read the newest agent-results/*/validation/results.json that has a NON-EMPTY detection.solved_challenges and whose detection.challenges_solved is <= baseline_solved (ignore obviously-partial files); return those names. It's OK if this list is slightly shorter than baseline_solved — the loop self-corrects after the first merge. If none is usable, return an empty array and note it.
Return infra_up, baseline_solved (from the chronicle), solved_challenges, the artifacts bucket, and any notes. Do NOT stand up or tear down infra.`,
  { label: 'prep', phase: 'Prep', schema: PREP_SCHEMA },
)
if (!prep || !prep.infra_up) {
  log(`ABORT: AWS infra is not up (${prep ? prep.notes : 'prep agent failed'}). Stand up tf/environments/dev first, then re-run.`)
  return { aborted: true, reason: 'infra-down' }
}

let solved = prep.baseline_solved
const startSolved = solved
// The set of already-solved challenge names — the planner and tiny-loops must
// avoid counting these as wins. Updated after every successful merge.
let solvedNames = prep.solved_challenges || []
log(`Baseline: ${solved}/${TOTAL} (${pct(solved)}%). Target: ${TARGET_PCT}%. Auditors/round: ${AUDITORS}. Max rounds: ${MAX_ROUNDS}. Already solved: ${solvedNames.length} known.`)

const merges = []
let round = 0
let dry = 0

while (pct(solved) < TARGET_PCT && round < MAX_ROUNDS && dry < DRY_LIMIT) {
  if (budget.total && budget.remaining() < 150_000) { log(`Stopping: token budget nearly exhausted (${Math.round(budget.remaining() / 1000)}k left).`); break }
  round++
  phase(`Round ${round}`)

  // PLAN
  const plan = await agent(
    `You are selecting this round's parallel auditor work. Read agent-results/*/validation/gap-analysis.md (newest) and docs/CHRONICLE.md.
Propose up to ${AUDITORS} MODULE-DISJOINT improvement opportunities (no two may edit the same scanner module) that are generic (help any web app) and NOT already tried-and-failed in the chronicle.${MODULE_HINT ? ' Prefer these modules: ' + MODULE_HINT.join(', ') + '.' : ''}

CRITICAL — target ONLY unsolved challenges. These challenges are ALREADY SOLVED and must NOT be targeted (re-solving them is worth zero): [${solvedNames.join(', ') || 'none known'}]. Every challenge in target_challenges must be one Diana does NOT already solve. If you cannot find unsolved challenges a module could plausibly flip, return fewer opportunities (or an empty list) rather than padding with already-solved ones.

For each: the single module, a title, the specific UNSOLVED Juice Shop challenge names it should flip, and a one-line rationale.`,
    { label: `plan:r${round}`, phase: 'Plan', schema: PLAN_SCHEMA },
  )
  // Drop any opportunity whose targets are all already-solved (defensive).
  const solvedLower = new Set(solvedNames.map(s => (s || '').toLowerCase()))
  const picks = ((plan && plan.opportunities) || [])
    .map(p => ({ ...p, target_challenges: (p.target_challenges || []).filter(c => !solvedLower.has((c || '').toLowerCase())) }))
    .filter(p => p.target_challenges.length > 0)
    .slice(0, AUDITORS)
  if (picks.length === 0) { log(`Round ${round}: planner found no UNSOLVED opportunities. Stopping.`); break }
  log(`Round ${round}: ${picks.length} auditors — ${picks.map(p => p.module).join(', ')}`)

  // IMPROVE + GATES + TINYLOOP (parallel across auditors)
  const results = (await parallel(picks.map(p => () => runAuditor(p, round, solvedNames)))).filter(Boolean)
  const green = results.filter(r => r.flipped)
  log(`Round ${round}: ${green.length}/${picks.length} auditors flipped a target (${green.map(g => g.module).join(', ') || 'none'}).`)
  for (const r of results.filter(x => !x.flipped)) log(`  · ${r.module}: ${r.reason}`)
  if (green.length === 0) { dry++; log(`Round ${round}: no green auditors (dry ${dry}/${DRY_LIMIT}).`); continue }

  // INTEGRATE — runs in its OWN worktree so it never moves the primary working
  // tree off main (an early run left the primary checked out on the integration
  // branch, stranding later commits). Fetch + merge the REMOTE auto/* branches.
  const integ = await agent(
    `You are in a dedicated git worktree — do NOT touch or checkout branches in any other working tree. Create integration branch "auto/integration-r${round}" from origin/main (git fetch origin first) and merge these validated remote branches into it: ${green.map(g => 'origin/' + g.branch).join(', ')}.
They are module-disjoint so merges should be clean; if any conflict is non-trivial, drop that branch and note it. Run the full unit suite (.venv/bin/python -m pytest tests/unit -q) and confirm it passes. Push the integration branch to origin (CodeBuild builds from the remote). Report the branch and which branches were actually merged. Do NOT check out or modify main.`,
    { label: `integrate:r${round}`, phase: 'Integrate', isolation: 'worktree', schema: INTEGRATE_SCHEMA },
  )
  if (!integ || !integ.ok) { log(`Round ${round}: integration failed (${integ ? integ.detail : 'agent failed'}).`); dry++; continue }

  // SMOKE — cheap single-module scan of the integrated image, to fail fast on a
  // crasher (e.g. a bad AI-payload template that aborts the whole scan) BEFORE
  // committing to a ~105-min full validation.
  const smokeModule = green[0].module
  const smoke = await agent(
    `Smoke-test the integrated image on branch ${integ.branch} following .claude/skills/agent-tinyloop/SKILL.md with MODULES="${smokeModule}". Build from the remote branch and run the single-module scan on a cached crawl. You are NOT checking for flips — only that the scan RUNS TO COMPLETION with no crash/exception (watch for AI payload-generation errors, JSON decode errors, orchestrator tracebacks; "Scan completed successfully" or a normal Results Summary means healthy). Set healthy=false if the scan aborts with an error. If you launch an ECS task and give up/time out, STOP it (aws ecs stop-task) before returning.`,
    { label: `smoke:r${round}`, phase: 'Smoke', agentType: 'agent-tinyloop', schema: SMOKE_SCHEMA },
  )
  if (!smoke || !smoke.healthy) {
    log(`Round ${round}: SMOKE FAILED — integrated image crashes (${smoke ? smoke.detail : 'agent failed'}). Skipping full scan; not merging.`)
    dry++; continue
  }

  // BIG SCAN (full validation, merge gate)
  const val = await agent(
    `Run a FULL validation (all modules, fresh crawl) on branch ${integ.branch} following .claude/skills/agent-validation/SKILL.md. Build from the remote branch, run the ECS task, fetch results from S3.

PATIENCE: a full validation takes ~90-110 minutes. Poll the ECS task until it reaches STOPPED (or ~130 min elapsed) — do NOT give up at 20-40 min. Fetch results.json from S3 with a few retries after the task stops (S3 write can lag the task exit).

NO ORPHANED TASKS: you launched this ECS task — you own it. If you give up, time out, or hit an error, you MUST 'aws ecs stop-task --cluster diana-cluster --task <arn>' before returning, so it does not run unattended and bill.

Report challenges_solved as 'solved' and the EXACT full list of solved challenge names (detection.solved_challenges, verbatim) as 'solved_challenges' — do NOT diff or filter it, the workflow computes newly-solved/regressions itself. Report duration_s. If the scan genuinely failed/crashed (no results), report solved=-1 and solved_challenges=[] so this round is treated as no-merge (NOT solved=0, which would look like a real regression).`,
    { label: `bigscan:r${round}`, phase: 'BigScan', agentType: 'agent-validation', schema: BIGSCAN_SCHEMA },
  )
  if (!val || val.solved < 0) { log(`Round ${round}: big scan did not produce a valid result (${val ? val.detail : 'agent failed'}).`); dry++; continue }

  // Compute newly-solved and regressions IN CODE from the full solved list vs the
  // tracked baseline — don't trust the agent to diff (it mislabeled once).
  const scanSolved = val.solved_challenges || []
  const scanSet = new Set(scanSolved.map(c => (c || '').toLowerCase()))
  const baseSet = new Set(solvedNames.map(c => (c || '').toLowerCase()))
  const newlySolved = scanSolved.filter(c => !baseSet.has((c || '').toLowerCase()))
  const regressions = solvedNames.filter(c => !scanSet.has((c || '').toLowerCase()))
  const improved = val.solved > solved
  const clean = regressions.length === 0
  if (improved && clean) {
    const mg = await agent(
      `In the PRIMARY working tree (do not create a worktree): 'git fetch origin', 'git checkout main', 'git merge --no-ff origin/${integ.branch}', resolve trivially if needed, then append a Chronicle entry to docs/CHRONICLE.md summarizing round ${round}: solve rate ${pct(solved)}% -> ${pct(val.solved)}% (+${val.solved - solved}), modules ${green.map(g => g.module).join(', ')}, newly solved ${newlySolved.join(', ') || '(count rose)'}. Commit the chronicle on main, then 'git push origin main'. Leave the working tree checked out on main. Report merged=true only after the push to main succeeds.`,
      { label: `merge:r${round}`, phase: 'BigScan', schema: MERGE_SCHEMA },
    )
    if (mg && mg.merged) {
      merges.push({ round, from: solved, to: val.solved, modules: green.map(g => g.module), newly_solved: newlySolved })
      solved = val.solved
      // Adopt the scan's full solved set as the authoritative new baseline, so
      // next round's planner and tiny-loops exclude everything now solved.
      solvedNames = scanSolved
      dry = 0
      log(`Round ${round}: MERGED. Now ${solved}/${TOTAL} (${pct(solved)}%). New: ${newlySolved.join(', ') || '(count rose)'}.`)
    } else {
      log(`Round ${round}: merge step did not complete (${mg ? mg.detail : 'agent failed'}); integration branch ${integ.branch} left for review.`)
      dry++
    }
  } else {
    log(`Round ${round}: not merging — improved=${improved} (solved ${val.solved} vs ${solved}), regressions=${regressions.join(', ') || 'none'}. Branch ${integ.branch} left for review.`)
    dry++
  }
}

const hitTarget = pct(solved) >= TARGET_PCT
log(`DONE after ${round} round(s). ${startSolved} -> ${solved}/${TOTAL} (${pct(solved)}%). Target ${TARGET_PCT}% ${hitTarget ? 'REACHED' : 'not reached'}.`)

// Teardown — always tear the AWS sandbox down at the end of a run so the meter
// stops. Runs after any auto-merges are already pushed to origin. Skipped only
// if the operator passed teardown:false. (Infra-down abort returns earlier, so
// there is nothing to tear down in that path.)
let teardown = null
if (TEARDOWN) {
  phase('Teardown')
  teardown = await agent(
    `Tear down the AWS dev sandbox now that the solve-loop run is complete. All merges are already pushed to origin, so nothing is lost. Your #1 job is that NO BILLABLE resource is left running (RDS/Aurora, ElastiCache Redis, ALB, NAT gateway, ECS tasks). Be patient and persistent — **Aurora cluster deletion alone takes ~8-12 minutes**, longer than a single command; do NOT give up early.

1. STOP LEFTOVER TASKS FIRST (they bill and block VPC/SG deletion): for each ARN in \`aws ecs list-tasks --cluster diana-cluster --region us-east-1 --query taskArns --output text\`, run \`aws ecs stop-task --cluster diana-cluster --region us-east-1 --task <arn>\`, then wait until zero tasks remain.
2. Clear a stale state lock if any command reports one: \`terraform -chdir=tf/environments/dev force-unlock -force <LOCK_ID>\`.
3. Run \`terraform -chdir=tf/environments/dev destroy -input=false -auto-approve -lock-timeout=180s\`. If your command environment cuts it off before it finishes, that's expected for the Aurora wait — simply RE-RUN the same destroy (it resumes); repeat up to ~8 times, waiting ~60s between attempts, until \`terraform state list\` is empty. On DependencyViolation/ClusterContainsTasks, go back to step 1 then re-run.
4. FALLBACK if terraform still can't remove RDS after several retries: delete it directly so billing stops — \`aws rds delete-db-instance --db-instance-identifier diana-db-0 --skip-final-snapshot --delete-automated-backups --region us-east-1\` then \`aws rds delete-db-cluster --db-cluster-identifier diana-db --skip-final-snapshot --region us-east-1\`; then resume terraform destroy for the rest.
5. VERIFY before returning: report ok=true ONLY when ALL of these are empty — \`terraform state list\`, \`aws ecs list-tasks --cluster diana-cluster\`, \`aws rds describe-db-clusters --query "DBClusters[?contains(DBClusterIdentifier,'diana')]"\`, \`aws elasticache describe-replication-groups --query "ReplicationGroups[?contains(ReplicationGroupId,'diana')]"\`, and \`aws elbv2 describe-load-balancers --query "LoadBalancers[?contains(LoadBalancerName,'diana')]"\`. Otherwise ok=false, and in detail list EXACTLY which billable resources remain so the operator can finish them.`,
    { label: 'teardown', phase: 'Teardown', schema: TEARDOWN_SCHEMA },
  )
  log(teardown && teardown.ok ? `Teardown complete: ${teardown.detail}` : `TEARDOWN MAY HAVE FAILED — check AWS manually: ${teardown ? teardown.detail : 'agent failed'}`)
}

return {
  hitTarget, targetPct: TARGET_PCT,
  startSolved, finalSolved: solved, finalPct: pct(solved),
  roundsRun: round, merges,
  teardown: teardown ? teardown.ok : 'skipped',
  stoppedBecause: hitTarget ? 'target-reached' : (round >= MAX_ROUNDS ? 'max-rounds' : (dry >= DRY_LIMIT ? 'dry-rounds' : 'budget')),
}
