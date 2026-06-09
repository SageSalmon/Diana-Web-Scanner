# Getting Started with Diana

## Prerequisites

- Python 3.12+
- AWS account with Bedrock access (Claude model enabled)
- AWS credentials configured (`~/.aws/credentials` or environment variables)
- Docker (optional, for containerized deployment)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/diana-scanner.git
cd diana-scanner

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # macOS/Linux

# Install in development mode
pip install -e ".[dev]"
```

### Docker

```bash
docker build -t diana .
docker run --rm -v ~/.aws:/root/.aws diana scan https://target.com
```

## AWS Configuration

Diana uses Amazon Bedrock for AI capabilities. Ensure you have:

1. **Bedrock model access** enabled for Claude in your AWS region
2. **IAM permissions** for `bedrock:InvokeModel` and `bedrock:InvokeModelWithResponseStream`

```bash
# Verify Bedrock access
aws bedrock list-foundation-models --query "modelSummaries[?contains(modelId, 'claude')]" --region us-east-1
```

### Minimal IAM Policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.claude-*"
    }
  ]
}
```

## Quick Start

### Basic Scan

```bash
# Simple scan against a target
diana scan https://example.com

# Scan with specific modules
diana scan https://example.com --modules xss,sqli,headers

# Scan with verbose output
diana scan https://example.com -v

# Scan with custom depth and rate limiting
diana scan https://example.com --depth 3 --rate-limit 10
```

### Configuration File

Create `diana.yaml` for reusable scan profiles:

```yaml
target: https://example.com
scan:
  depth: 3
  rate_limit: 10  # requests per second
  timeout: 30     # seconds per request
  modules:
    - xss
    - sqli
    - ssrf
    - headers
    - info_disclosure

ai:
  model_id: anthropic.claude-sonnet-4-6-20250514
  region: us-east-1
  max_tokens: 4096

auth:
  type: bearer
  token: ${AUTH_TOKEN}  # environment variable

scope:
  include:
    - "https://example.com/*"
  exclude:
    - "https://example.com/logout"
    - "https://example.com/admin/delete*"

reporting:
  format: html
  output: ./reports/
```

```bash
# Run with config file
diana scan --config diana.yaml
```

### API Server Mode

```bash
# Start the API server
diana serve --port 8000

# Submit a scan via API
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "modules": ["xss", "sqli"]}'
```

## CLI Reference

```
diana — AI-Enabled Web Vulnerability Scanner

COMMANDS:
  scan        Run a vulnerability scan against a target
  serve       Start the REST API server
  report      Generate or view reports from previous scans
  config      Manage scanner configuration
  version     Show version information

SCAN OPTIONS:
  --target, -t       Target URL to scan
  --config, -c       Path to configuration file
  --modules, -m      Comma-separated list of scan modules
  --depth, -d        Maximum crawl depth (default: 3)
  --rate-limit, -r   Max requests per second (default: 10)
  --timeout          Request timeout in seconds (default: 30)
  --output, -o       Output file path for report
  --format, -f       Report format: html, json, sarif (default: html)
  --verbose, -v      Verbose output
  --no-ai            Disable AI analysis (traditional scan only)
```

## Example Output

```
$ diana scan https://testapp.example.com -v

  ╔═══════════════════════════════════════════╗
  ║   Diana — AI-Enabled Web Scanner        ║
  ║   v0.1.0                                  ║
  ╚═══════════════════════════════════════════╝

  Target: https://testapp.example.com
  Modules: xss, sqli, ssrf, headers, info_disclosure
  AI Model: Claude Sonnet 4.6 (via Bedrock)

  [1/8] Discovering target...
    ✓ Resolved to 93.184.216.34
    ✓ TLS 1.3, valid certificate
    ✓ Server: nginx/1.24.0

  [2/8] Crawling application...
    ✓ Found 47 unique URLs
    ✓ Found 12 forms
    ✓ Found 3 API endpoints
    ✓ Technologies: React, Express, PostgreSQL

  [3/8] Analyzing attack surface...
    ✓ AI identified 8 high-interest endpoints
    ✓ 3 endpoints accept user input without visible sanitization

  [4/8] Generating vulnerability hypotheses...
    ✓ 14 hypotheses generated

  [5/8] Crafting payloads...
    ✓ 42 context-aware payloads generated

  [6/8] Testing...
    ████████████████████████████████ 42/42

  [7/8] Validating findings...
    ✓ 6 confirmed, 3 rejected as false positives

  [8/8] Generating report...
    ✓ Report saved to ./reports/scan_20260507_143022.html

  ──────────────────────────────────────────────
  RESULTS SUMMARY
  ──────────────────────────────────────────────
  Critical:  1  ██
  High:      2  ████
  Medium:    2  ████
  Low:       1  ██
  Info:      3  ██████

  Total findings: 9 (6 vulnerabilities, 3 informational)
  False positives rejected by AI: 3
  Scan duration: 2m 34s
```

## Next Steps

- Read the [Architecture Guide](./ARCHITECTURE.md) to understand how Diana works
- Check the [API Reference](./API.md) for REST API documentation
- Review the vulnerability modules in `src/diana/scanners/`
