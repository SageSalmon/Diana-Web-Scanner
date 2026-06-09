# Agent Router — Feature-Based Endpoint-to-Agent Allocation

## Problem

Every endpoint goes to every agent. A scan with 80 endpoints and 4 agents means 320 evaluations — most waste LLM tokens on irrelevant endpoint-agent pairs. We need a router that predicts which agents will produce findings for which endpoints.

## Architecture

```
                    ┌────────────────────────────────┐
Endpoint            │        Router / Classifier     │
discovered ──────►  │                                │
                    │  Feature extraction             │
                    │        ↓                        │
                    │  Score each agent using          │
                    │  logistic regression trained     │
                    │  on agent_performance data       │
                    │        ↓                        │
                    │  Assign to top-scoring agents    │
                    └──┬───┬───┬───┬─────────────────┘
                       │   │   │   │
                  ┌────┘   │   │   └────┐
                  ▼        ▼   ▼        ▼
              Discovery  SQLi  XSS  AccessCtrl
              Queue      Queue Queue Queue
              scored     scored scored scored
```

## Feature Vector

Each endpoint is described by a feature vector extracted at crawl time. No LLM calls required — all features are derived from HTTP responses and endpoint structure.

### Endpoint Features

| Feature | Type | How Extracted | Why It Matters |
|---------|------|--------------|----------------|
| `has_params` | bool | URL contains `?` or POST body | Injection/XSS requires params |
| `param_count` | int | Count of query/body params | More params = more attack surface |
| `has_id_param` | bool | Param named id, uid, user_id, etc. | IDOR indicator |
| `has_url_param` | bool | Param named url, redirect, src, etc. | SSRF/redirect indicator |
| `has_file_param` | bool | Param named file, path, template, etc. | Path traversal indicator |
| `has_auth_param` | bool | Param named email, password, token, etc. | Auth attack indicator |
| `method_is_post` | bool | HTTP method | Stored XSS, data mutation |
| `method_is_put_delete` | bool | HTTP method | Access control indicator |
| `path_depth` | int | Count of `/` segments | Deeper = more specific resource |
| `path_has_numeric_id` | bool | `/api/Users/1` pattern | IDOR target |
| `path_keyword_admin` | bool | Contains admin, manage, dashboard | Privilege escalation |
| `path_keyword_auth` | bool | Contains login, signin, register | Auth attack target |
| `path_keyword_upload` | bool | Contains upload, file, import | File upload attacks |
| `path_keyword_search` | bool | Contains search, query, find | Injection/XSS reflection |
| `path_keyword_api` | bool | Under /api/ or /rest/ | API-specific vulns |

### Response Features

| Feature | Type | How Extracted | Why It Matters |
|---------|------|--------------|----------------|
| `response_size` | int | Content-Length or len(body) | Large responses = more data exposure |
| `response_time_ms` | float | Request latency | Slow = DB query = injection target |
| `status_code` | int | HTTP status | 200 vs 401 vs 500 tells a lot |
| `content_type_json` | bool | Content-Type header | API endpoint |
| `content_type_html` | bool | Content-Type header | Traditional page, XSS relevant |
| `has_set_cookie` | bool | Set-Cookie header | Session management |
| `has_cors_headers` | bool | CORS headers present | Cross-origin attack surface |
| `response_has_emails` | bool | Regex match in body | Data exposure indicator |
| `response_has_errors` | bool | SQL error patterns in body | Error-based injection |
| `response_changes_with_auth` | bool | Different response for admin vs none | Access control issue |
| `response_size_diff_by_auth` | float | Size ratio (admin response / unauth response) | IDOR indicator |

### Engagement Context Features

| Feature | Type | How Extracted | Why It Matters |
|---------|------|--------------|----------------|
| `tech_express` | bool | Tech stack fingerprint | Framework-specific vulns |
| `tech_django` | bool | Tech stack fingerprint | |
| `tech_spring` | bool | Tech stack fingerprint | |
| `tech_php` | bool | Tech stack fingerprint | |
| `tech_angular` | bool | JS framework | SPA-specific testing |
| `tech_react` | bool | JS framework | |
| `db_sqlite` | bool | Error messages / fingerprint | SQLi payload selection |
| `db_postgres` | bool | Error messages / fingerprint | |
| `db_mysql` | bool | Error messages / fingerprint | |
| `db_mongodb` | bool | Error messages / fingerprint | NoSQL payloads |
| `has_waf` | bool | WAF detected | Payload encoding needed |
| `is_spa` | bool | SPA detected | DOM XSS, hash routes |
| `total_endpoints` | int | Endpoint count | App size context |
| `param_endpoint_ratio` | float | Parameterized / total | API-heavy vs static site |

### Historical Features (learned across engagements)

| Feature | Type | Source | Why It Matters |
|---------|------|--------|----------------|
| `agent_success_rate_on_pattern` | float | agent_performance table | Did this agent find vulns on similar endpoints before? |
| `agent_success_rate_on_tech` | float | agent_performance table | Did this agent work well on this tech stack? |
| `agent_avg_findings_per_endpoint` | float | agent_performance table | Productivity metric |
| `agent_false_positive_rate` | float | agent_performance table | Quality metric |
| `agent_tokens_per_finding` | float | token_usage table | Cost efficiency |
| `agent_chain_value` | float | findings table | Did this agent's findings lead to downstream discoveries? |
| `pattern_ever_had_finding` | bool | findings table | Has any agent ever found something on this pattern? |
| `time_since_last_scan` | float | scans table | Fresh target vs re-test |

## Feature Extraction

```python
@dataclass
class EndpointFeatures:
    """Feature vector for a single endpoint."""

    # Endpoint structure
    has_params: bool
    param_count: int
    has_id_param: bool
    has_url_param: bool
    has_file_param: bool
    has_auth_param: bool
    method_is_post: bool
    method_is_put_delete: bool
    path_depth: int
    path_has_numeric_id: bool
    path_keyword_admin: bool
    path_keyword_auth: bool
    path_keyword_upload: bool
    path_keyword_search: bool
    path_keyword_api: bool

    # Response characteristics
    response_size: int
    response_time_ms: float
    status_code: int
    content_type_json: bool
    content_type_html: bool
    has_set_cookie: bool
    has_cors_headers: bool
    response_has_emails: bool
    response_has_errors: bool
    response_changes_with_auth: bool
    response_size_diff_by_auth: float

    # Engagement context
    tech_stack: list[str]
    db_type: str
    has_waf: bool
    is_spa: bool
    total_endpoints: int
    param_endpoint_ratio: float

    def to_vector(self) -> list[float]:
        """Convert to numeric vector for the classifier."""
        ...
```

Feature extraction happens once during crawl — no LLM calls. The crawler already collects most of this data. Response features require one unauthenticated + one authenticated request per endpoint (which the crawler already makes).

## Model

Logistic regression per agent. Simple, interpretable, trainable on small data.

```python
class AgentRouter:
    """Predicts which agents should test each endpoint."""

    def __init__(self):
        # One classifier per agent
        self.models: dict[str, LogisticRegression] = {}

    def train(self, performance_data: list[dict]):
        """Train on historical agent_performance data.

        Each record: {features: [...], agent: str, found_something: bool}
        """
        for agent_name in AGENT_NAMES:
            agent_data = [d for d in performance_data if d["agent"] == agent_name]
            if len(agent_data) < 10:
                continue  # Not enough data — use heuristic

            X = [d["features"] for d in agent_data]
            y = [1 if d["found_something"] else 0 for d in agent_data]
            self.models[agent_name] = LogisticRegression().fit(X, y)

    def score(self, features: EndpointFeatures) -> dict[str, float]:
        """Score an endpoint for each agent. Returns probability of finding."""
        vector = features.to_vector()
        scores = {}
        for agent_name in AGENT_NAMES:
            if agent_name in self.models:
                scores[agent_name] = self.models[agent_name].predict_proba([vector])[0][1]
            else:
                scores[agent_name] = self._heuristic_score(features, agent_name)
        return scores

    def route(self, features: EndpointFeatures, threshold: float = 0.3) -> list[str]:
        """Return list of agents that should test this endpoint."""
        scores = self.score(features)
        return [agent for agent, score in scores.items() if score >= threshold]
```

### Why Logistic Regression

| Property | Why It Matters |
|----------|---------------|
| **Interpretable** | Can explain WHY an endpoint was routed to an agent ("high score because has_params=true and path_keyword_search=true") |
| **Small data** | Works with 50-100 training samples (a few engagements) |
| **Fast** | Microsecond inference — no GPU needed |
| **No overfitting** | With L2 regularization, generalizes well from small data |
| **Feature importance** | Coefficient weights show which features matter most per agent |
| **Probability output** | `predict_proba` gives confidence, not just yes/no |

Upgrade path: if logistic regression plateaus, swap to gradient boosted trees (XGBoost) for non-linear interactions — same feature vector, better accuracy, slightly less interpretable.

## Cold Start

First engagement has no historical data. The heuristic scoring handles this:

```python
def _heuristic_score(self, features: EndpointFeatures, agent: str) -> float:
    """Rule-based scoring when no historical data exists."""
    score = 0.1  # baseline

    if agent == "sqli_agent":
        if features.has_params: score += 0.3
        if features.path_keyword_search: score += 0.2
        if features.path_keyword_auth: score += 0.2
        if features.response_has_errors: score += 0.2
        if features.response_time_ms > 500: score += 0.1  # slow = DB query

    elif agent == "xss_agent":
        if features.has_params: score += 0.3
        if features.content_type_html: score += 0.2
        if features.method_is_post: score += 0.1
        if features.path_keyword_search: score += 0.2

    elif agent == "access_control":
        if features.path_has_numeric_id: score += 0.3
        if features.response_changes_with_auth: score += 0.3
        if features.path_keyword_admin: score += 0.2
        if features.method_is_put_delete: score += 0.1

    elif agent == "discovery_agent":
        score = 0.5 if not features.has_params else 0.1

    return min(score, 1.0)
```

After the first engagement, the heuristic is blended with the model:

```python
if model.sample_count < 10:
    return heuristic_score  # Pure heuristic
elif model.sample_count < 50:
    return 0.6 * heuristic_score + 0.4 * model_score  # Blended
else:
    return model_score  # Trust the model
```

## Recording Training Data

After each scan, extract features for every endpoint and record the outcome:

```python
def record_outcomes(scan_id: str, state: ScanState):
    """Record training data for the router after scan completion."""
    endpoints = state.get_all_endpoints(scan_id)
    findings = state.get_findings(scan_id)
    queue_stats = state.get_agent_coverage(scan_id)

    for endpoint in endpoints:
        features = extract_features(endpoint)
        for agent_name in AGENT_NAMES:
            # Did this agent find something on this endpoint?
            agent_findings = [
                f for f in findings
                if f["module"] == agent_name
                and f["endpoint_url"] == endpoint["url"]
            ]
            state.store_training_sample(
                engagement_id=...,
                agent_name=agent_name,
                endpoint_pattern=classify_pattern(endpoint["url"]),
                features=features.to_vector(),
                found_something=len(agent_findings) > 0,
                finding_count=len(agent_findings),
                severity_max=max((f["severity"] for f in agent_findings), default="none"),
            )
```

## Schema

```sql
-- Training data for the router
router_training (
    id              serial primary key,
    engagement_id   text not null,
    scan_id         text not null,
    agent_name      text not null,
    endpoint_pattern text not null,
    features        jsonb not null,           -- full feature vector
    found_something boolean not null,         -- label
    finding_count   integer default 0,
    severity_max    text default 'none',
    tokens_spent    integer default 0,
    created_at      timestamptz default now()
)

-- Trained model weights (serialized)
router_models (
    id              serial primary key,
    agent_name      text not null unique,
    model_blob      bytea not null,           -- pickled LogisticRegression
    feature_names   jsonb not null,           -- ordered feature names
    sample_count    integer default 0,
    accuracy        float default 0,
    last_trained    timestamptz default now()
)
```

## Observability

After each scan, the router reports:

```
Router Performance:
  sqli_agent:
    Endpoints assigned: 12/80 (15%)
    Findings: 3
    Hit rate: 25% (3/12 endpoints produced findings)
    Tokens saved: ~280K (skipped 68 irrelevant endpoints)

  access_control:
    Endpoints assigned: 30/80 (38%)
    Findings: 8
    Hit rate: 27%

  discovery_agent:
    Endpoints assigned: 5/80 (6%)
    Findings: 4
    Hit rate: 80%

  xss_agent:
    Endpoints assigned: 8/80 (10%)
    Findings: 0
    Hit rate: 0% — consider lowering threshold

  Total token savings: ~500K input tokens (~$0.31 at DeepSeek rates)
```

## Evolution Path

| Stage | Data Available | Approach |
|-------|---------------|----------|
| **First scan** | None | Pure heuristic scoring |
| **2-5 scans** | 100-500 samples | Heuristic-model blend (60/40) |
| **5-20 scans** | 500-2000 samples | Logistic regression takes over |
| **20+ scans** | 2000+ samples | Upgrade to XGBoost for non-linear patterns |
| **100+ scans** | 10000+ samples | Per-tech-stack models, feature interaction discovery |

The feature vector and training pipeline stay the same at every stage — only the model complexity changes.
