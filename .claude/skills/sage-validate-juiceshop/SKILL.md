---
name: sage-validate-juiceshop
description: Run AI-enabled Diana scan against Juice Shop and compare to known vulns
user_invocable: true
---

# Validate Diana vs Juice Shop

Run a full AI-enabled Diana scan against OWASP Juice Shop, compare findings against the known challenge list, identify classes of missed vulnerabilities, and rank improvements by general applicability across web apps.

## Instructions

### Step 1: Verify Juice Shop is Running

Check that Juice Shop is responding at `http://localhost:3000` (or the target URL provided as an argument). If not running, start it:
```bash
docker compose -f docker-compose.dev.yaml up -d juice-shop
```
Wait for a 200 response before continuing.

### Step 2: Reset Juice Shop and Run Diana Scan

Restart Juice Shop for a clean challenge state, then run a full AI-enabled scan:
```bash
docker compose -f docker-compose.dev.yaml restart juice-shop
# Wait for restart
sleep 10
# Verify clean state
curl -s http://localhost:3000/api/Challenges | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'Solved: {sum(1 for c in d[\"data\"] if c[\"solved\"])}')"
# Run scan
source .venv/bin/activate
DIANA_AI_ENABLED=true python -m diana.cli scan http://localhost:3000 \
  -e engagements/local-juiceshop.yaml \
  --local --modules headers,info_disclosure,xss,sqli,ssrf,auth \
  -d 3 -r 20 -f json -o reports/
```
Record finding count, false positives rejected, and duration.

### Step 3: Capture Results

Fetch the challenge state and full challenge list after the scan:
```bash
curl -s http://localhost:3000/api/Challenges | python3 -c "
import json, sys
from collections import defaultdict
data = json.load(sys.stdin)
challenges = data.get('data', [])
by_cat = defaultdict(list)
for c in challenges:
    by_cat[c['category']].append(c)
total = len(challenges)
solved = [c for c in challenges if c.get('solved')]
print(f'Total: {total}, Solved: {len(solved)}')
for c in solved:
    print(f'  SOLVED [{c[\"difficulty\"]}*] {c[\"name\"]} -- {c[\"category\"]}')
print()
for cat in sorted(by_cat.keys()):
    count = len(by_cat[cat])
    s = sum(1 for c in by_cat[cat] if c.get('solved'))
    print(f'  {cat}: {s}/{count}')
"
```

Also extract Diana's finding titles from the latest report in `reports/`.

### Step 4: Update docs/SCAN_RESULTS.md

Update `docs/SCAN_RESULTS.md` with the following sections:

#### Summary Table
Total challenges, solved by Diana, Diana findings, false positives rejected, coverage %, duration.

#### Challenges Solved
Table of challenges Juice Shop confirmed as solved, with how Diana triggered each one.

#### Per-Category Breakdown
For each Juice Shop category, a table listing every challenge with:
- Name, difficulty (stars), status: **SOLVED** / **RELATED** / **NOT FOUND**
- SOLVED = Juice Shop confirmed (`"solved": true`)
- RELATED = Diana found something in the same area but didn't trigger the challenge
- NOT FOUND = missed entirely

#### Diana's Non-Challenge Findings
Security issues Diana found that don't map to specific challenges (headers, CORS, info disclosure, etc.)

#### Missed Vulnerability Classes — Ranked by General Applicability

This is the key output. Group all NOT FOUND challenges by the **class of scanner improvement** needed to find them. For each class:

| Rank | Improvement Class | Juice Shop Challenges Missed | Applicability to Other Web Apps | Effort |
|------|------------------|-----------------------------|---------------------------------|--------|

**Ranking criteria — prioritize by general applicability:**
- An improvement that would help scan ANY web app (e.g., "Playwright rendering for SPA routes") ranks higher than one specific to Juice Shop's quirks
- An improvement that addresses OWASP Top 10 vulns across the industry ranks higher than niche attack types
- Consider how many real-world web apps would benefit from the fix, not just how many Juice Shop challenges it solves

Categories of improvement to consider:
- SPA/JS rendering (Playwright for hash routes, dynamic forms)
- Parameter discovery depth (POST body schemas, GraphQL introspection)
- Authentication attack modules (credential stuffing, password reset abuse, 2FA bypass)
- File upload testing
- Deserialization / component analysis
- OSINT / social engineering (likely out of scope — note as such)

For each class, explain: what the improvement is, how many Juice Shop challenges it would solve, and WHY it matters for scanning real-world apps beyond Juice Shop.

## Notes
- Juice Shop must be running locally on port 3000
- `.venv` must be set up with Diana installed
- `engagements/local-juiceshop.yaml` must have credentials configured
- This skill restarts Juice Shop — prior challenge solves will be cleared
- The AI scan takes ~15-25 minutes depending on Bedrock latency
