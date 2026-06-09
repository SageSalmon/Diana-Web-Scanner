# Diana vs. OWASP Juice Shop — Vulnerability Coverage Report

**Scan Date:** 2026-05-12
**Target:** Juice Shop (Docker, localhost:3000)
**Modules:** All 11 (7 static + 4 AI agents)
**AI:** LangChain + LangGraph ReAct agents via Amazon Bedrock (Claude Sonnet 4.6)
**Auth:** Auto-login via Auth Agent (JWT/cookie capture)
**SPA:** Playwright route discovery + DOM XSS testing
**Database:** PostgreSQL scan state — agents pull batches, share findings
**Source:** Juice Shop `/api/Challenges` endpoint (111 challenges)

---

## Summary

| Metric | Value |
|--------|-------|
| **Total Juice Shop Challenges** | 111 |
| **Solved by Diana** | 21 (18.9%) |
| **Diana Findings** | 87 |
| **False Positives Rejected by AI** | — |
| **Scan Duration** | 4564s (~76 min) |
| **Endpoints in DB** | 83 |
| **Agent Findings in DB** | 38 |
| **Modules that wrote to DB** | access_control, sqli_agent, xss_agent, discovery_agent |

### Progress

| Milestone | Challenges | How |
|-----------|:---------:|-----|
| Initial scanner | 3 | SQLi auth bypass, weak password, error handling |
| + Access control module | 6 | Role escalation, feedback delete/forge |
| + Parameter fuzzing | 8 | UNION SQLi on search, user credential dump |
| + Discovery module | 10 | Exposed metrics, security.txt |
| + SPA Playwright | 11 | DOM XSS |
| + AI agents (LangChain) | **21** | Null byte bypass, /ftp exploration, CAPTCHA bypass, deluxe fraud, backup files |

---

## Challenges Solved (confirmed by Juice Shop)

| Challenge | Category | Difficulty | How Diana Solved It |
|-----------|----------|:---------:|---------------------|
| **Error Handling** | Security Misconfiguration | 1* | `.env` probe triggered unhandled error |
| **Exposed Metrics** | Observability Failures | 1* | Discovery module found `/metrics` |
| **DOM XSS** | XSS | 1* | SPA crawler injected XSS at `/#/search` via Playwright |
| **Repetitive Registration** | Improper Input Validation | 1* | Registration without `passwordRepeat` accepted |
| **Zero Stars** | Improper Input Validation | 1* | Access control agent solved CAPTCHA, submitted rating=0 |
| **Confidential Document** | Sensitive Data Exposure | 1* | Discovery agent found acquisitions doc in `/ftp` |
| **Login Admin** | Injection | 2* | SQLi `' OR 1=1--` on login endpoint |
| **Password Strength** | Broken Authentication | 2* | Auth agent logged in with `admin123` |
| **Five-Star Feedback** | Broken Access Control | 2* | Access control agent DELETE on feedback |
| **Security Policy** | Miscellaneous | 2* | Discovery module found `security.txt` |
| **Admin Registration** | Improper Input Validation | 3* | Access control agent registered with `role=admin` |
| **Forged Feedback** | Broken Access Control | 3* | Access control agent spoofed UserId |
| **Database Schema** | Injection | 3* | SQLi agent UNION extracted `sqlite_master` |
| **Login Jim** | Injection | 3* | SQLi agent used OFFSET to target Jim's account |
| **Deluxe Fraud** | Improper Input Validation | 3* | Access control agent stole deluxe token via IDOR |
| **User Credentials** | Injection | 4* | SQLi agent UNION extracted Users table |
| **Easter Egg** | Broken Access Control | 4* | Discovery agent path traversal on `/ftp` |
| **Poison Null Byte** | Improper Input Validation | 4* | Discovery agent null byte injection on FTP extension filter |
| **Misplaced Signature File** | Observability Failures | 4* | Discovery agent found it in `/ftp` exploration |
| **Forgotten Developer Backup** | Sensitive Data Exposure | 4* | Discovery agent + null byte bypass |
| **Forgotten Sales Backup** | Sensitive Data Exposure | 4* | Discovery agent found coupon backup in `/ftp` |

---

## Findings by Severity (87 total)

| Severity | Count | Examples |
|----------|:-----:|---------|
| **CRITICAL** | 40 | SQLi auth bypass, UNION extraction, role escalation, null byte bypass, exposed credentials |
| **HIGH** | 24 | IDOR on 10+ endpoints, method tampering, stored XSS, /ftp directory listing |
| **MEDIUM** | 9 | Missing HSTS/CSP, CORS, CAPTCHA bypass, API docs exposed |
| **LOW** | 4 | Missing Referrer-Policy, Permissions-Policy |
| **INFO** | 10 | Email addresses in API responses, robots.txt paths |

---

## Remaining Challenges — By Reachability

### Reachable with More Agent Turns/Tuning (39 challenges)

These use attack patterns Diana's agents already know — they just need more turns, better prompts, or slight technique refinements.

| Challenge | Difficulty | Category | What's Needed |
|-----------|:---------:|----------|---------------|
| Web3 Sandbox | 1* | Broken Access Control | SPA route already discovered |
| Outdated Allowlist | 1* | Unvalidated Redirects | Redirect parameter testing |
| Missing Encoding | 1* | Improper Input Validation | URL encoding test on photo path |
| Bonus Payload | 1* | XSS | Specific iframe payload in search |
| Password Hash Leak | 2* | Sensitive Data Exposure | Agent saw it but didn't report as finding |
| Admin Section | 2* | Broken Access Control | Navigate `/#/administration` |
| Deprecated Interface | 2* | Security Misconfiguration | Find `/file-upload` endpoint |
| Empty User Registration | 2* | Improper Input Validation | Registration with empty fields |
| Reflected XSS | 2* | XSS | Search param reflection |
| View Basket | 2* | Broken Access Control | `/rest/basket/:id` IDOR |
| Exposed Credentials | 2* | Sensitive Data Exposure | Hardcoded creds in JS |
| API-only XSS | 3* | XSS | POST XSS to `/api/Users` email field |
| Client-side XSS Protection | 3* | XSS | Bypass client-side filter |
| Forged Review | 3* | Broken Access Control | PUT on review endpoint |
| Login Bender | 3* | Injection | SQLi with Bender's email prefix |
| Manipulate Basket | 3* | Broken Access Control | Add item to another basket |
| Payback Time | 3* | Improper Input Validation | Negative quantity in order |
| Product Tampering | 3* | Broken Access Control | PUT product description |
| CSRF | 3* | Broken Access Control | CSRF token validation test |
| Christmas Special | 4* | Injection | SQLi to find deleted product, then order |
| Ephemeral Accountant | 4* | Injection | SQLi with INSERT logic |
| CSP Bypass | 4* | XSS | Find legacy page, execute XSS |
| HTTP-Header XSS | 4* | XSS | XSS via User-Agent/Referer |
| Server-side XSS Protection | 4* | XSS | Server-side filter bypass |
| NoSQL DoS | 4* | Injection | MongoDB `$where` or `$regex` |
| NoSQL Manipulation | 4* | Injection | MongoDB injection on reviews |
| + 13 more 3-4* challenges | | | Various auth/access/data patterns |

### Out of Scope (51 challenges)

| Category | Count | Why |
|----------|:-----:|-----|
| Expert (5-6 star) | 32 | Require deep multi-step chaining, crypto analysis, RCE |
| OSINT | 6 | Require human research, image analysis |
| Interactive | 5 | Chatbot interaction, UI-only actions |
| File Upload | 3 | XXE, type/size bypass — new module needed |
| Crypto | 2 | Token/coupon reverse engineering |
| SCA/Dependency | 2 | Package vulnerability scanning |
| Anti-Automation | 1 | Race condition exploitation |

---

## Key AI Agent Achievements

The most impressive autonomous discoveries — things the AI figured out without hardcoded logic:

1. **Null byte injection on FTP** — Discovery agent found `/ftp` from robots.txt, noticed file extension filter blocked `.bak` downloads, tried null byte bypass `%00.md`, succeeded
2. **OFFSET-based user targeting** — SQLi agent discovered it could append `OFFSET 1` to auth bypass payload to login as specific users
3. **CAPTCHA solving** — Access control agent found `/rest/captcha` endpoint, read the answer from the response, used it to submit zero-star feedback
4. **Deluxe token theft** — Access control agent found deluxe token in IDOR response, used it to get free deluxe membership
5. **Attack chaining** — Discovery agent found `/ftp` → explored listing → found backup files → used null byte to bypass filter → downloaded coupon codes

---

## Database State After Scan

| Table | Records | Purpose |
|-------|:-------:|---------|
| scans | 1 | Scan metadata + auth tokens |
| endpoints | 83 | All discovered endpoints with params |
| findings | 38 | Agent findings (shared across all agents) |

Agents that wrote findings: `access_control`, `sqli_agent`, `xss_agent`, `discovery_agent`
