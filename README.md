# owasp-zap-multirole-scanner

OWASP ZAP automated security testing for REST APIs. Uses the [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) to run multi-phase active scans across different authentication roles, with token refresh, access control checks, and SARIF output for the GitHub Security tab.

Targets [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — a deliberately vulnerable web application designed for security testing practice.

## Security coverage

| Area | What covers it |
|------|---------------|
| Penetration-style testing | Active scan across 4 auth phases (admin, customer, unauth, invalid-token) |
| Injection risks | `sqli`, `cmd-injection`, `path-traversal`, `xxe`, `ldap`, `ssrf` rule categories |
| XSS | `xss` — reflected, persistent, and DOM-based rules; passive scan also fires on responses |
| Authentication testing | JWT Bearer auth; invalid-token phase tests expired/malformed tokens; unauthenticated phase tests all endpoints without auth |
| Session management | `-Tests "session"` — token-after-logout, concurrent sessions, JWT signature tamper |
| Authorization / access control | BOLA checks — cross-role (customer token vs admin endpoints) and cross-customer (customer1 vs customer2 resources) |
| API security testing | Manually authored OpenAPI spec covering 67 endpoints; all actively scanned across auth roles |
| Input validation / fuzz testing | `-Tests "fuzz"` — all injection rules at Insane strength for deeper payload coverage |
| Security misconfigurations | Passive scan flags missing headers (CSP, HSTS, etc.) and verbose error responses |
| Information leakage | Passive scan detects stack traces, X-Powered-By headers, and sensitive data in responses |
| Network exposure | OpenAPI spec maps the full attack surface; all 67 endpoints tested across roles |

## How it works

Each scan runs seven phases against the target's OpenAPI spec:

1. **Admin scan** — authenticated as a privileged role; tests admin-only endpoints
2. **Customer scan** — authenticated as a regular user; tests customer-facing endpoints
3. **Unauthenticated scan** — no token; verifies all protected endpoints reject unauthorized requests
4. **Invalid token scan** — a well-formed JWT with a bogus signature and `exp=1`; any `200` response signals an auth bypass
5. **Rate limiting probe** — 20 rapid auth requests before the scan starts; warns if no `429` is returned
6. **Cross-role BOLA checks** — customer token tested against admin-only endpoints; any `200` is a finding
7. **Cross-customer BOLA checks** — customer1 token tested against customer2's resources; any `200` is a finding

### Token acquisition

Juice Shop uses JWT authentication. Tokens are fetched by POSTing credentials to `/rest/user/login`, which follows the Resource Owner Password Credentials pattern — credentials in, short-lived JWT out, used as a Bearer token throughout the scan.

Since scans can outlast token expiry, tokens are refreshed every 12 minutes via the ZAP API throughout each authenticated phase.

## Repository structure

```
projects/
  <project>/
    automation.yaml              # ZAP Automation Framework plan
    config/
      <env>.properties           # Environment-specific config (URLs, usernames)
    specs/
      openapi.json               # Manually authored OpenAPI spec (tracked in repo)
    scripts/
      run-scan.ps1               # Local scan runner (Windows/PowerShell)
      generate-report.ps1        # Converts ZAP JSON output to a clean HTML report
      test-run-scan.ps1          # Unit tests for argument parsing and YAML generation
common/
  scan-policies/
    rest-api.xml                 # ZAP policy for REST APIs (import into ZAP desktop)
.github/
  workflows/
    security-scan.yml            # GitHub Actions CI workflow
reports/                         # Scan output (gitignored)
docker-compose.yml               # Juice Shop (dev + staging)
```

## Projects

| Project | Target | Roles | Environments |
|---------|--------|-------|--------------|
| juice-shop | OWASP Juice Shop REST API | admin, customer | dev, staging |

## Running locally (Windows)

### Prerequisites

- [OWASP ZAP](https://www.zaproxy.org/download/) installed at `C:\Program Files\ZAP\Zed Attack Proxy`
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed
- PowerShell 5.1+

### Setup

```powershell
# 1. Start Juice Shop
docker compose up -d juice-shop-dev

# 2. Register customer accounts (first run only)
#    See CONTRIBUTING.md for the registration commands

# 3. Set required environment variables
$env:JUICE_SHOP_ADMIN_PASSWORD    = "admin123"
$env:JUICE_SHOP_CUSTOMER_PASSWORD = "YourCustomerPassword"

# 4. Run the scan
.\projects\juice-shop\scripts\run-scan.ps1 -Env dev
```

### Selective testing

Use `-Tests` to run only specific checks instead of the full scan:

```powershell
# Access control (BOLA) checks only - no ZAP required
.\projects\juice-shop\scripts\run-scan.ps1 -Env dev -Tests "bola"

# Rate limiting probe only
.\projects\juice-shop\scripts\run-scan.ps1 -Env dev -Tests "rate-limit"

# XSS and SQL injection across admin + customer phases
.\projects\juice-shop\scripts\run-scan.ps1 -Env dev -Tests "xss,sqli"

# XSS on admin phase only
.\projects\juice-shop\scripts\run-scan.ps1 -Env dev -Tests "xss,admin"

# Auth bypass checks (unauthenticated + invalid token phases)
.\projects\juice-shop\scripts\run-scan.ps1 -Env dev -Tests "auth-bypass"

# Combine pre-scan checks with a ZAP rule category
.\projects\juice-shop\scripts\run-scan.ps1 -Env dev -Tests "bola,rate-limit,xss"
```

**Available test names:**

| Name | What it runs |
|------|-------------|
| `all` | Everything (default) |
| `bola` | Cross-role + cross-customer access control check |
| `rate-limit` | 20 rapid auth requests - warns if no 429 |
| `xss` | Cross-site scripting rules |
| `sqli` | SQL injection rules |
| `path-traversal` | Path traversal rules |
| `cmd-injection` | OS command injection rules |
| `ssrf` | Server-side request forgery rules |
| `xxe` | XML external entity injection rules |
| `ldap` | LDAP injection rules |
| `admin` | Admin-role active scan (all rules) |
| `customer` | Customer-role active scan (all rules) |
| `unauth` | Unauthenticated active scan (all rules) |
| `invalid-token` | Expired/invalid token active scan (all rules) |
| `auth-bypass` | Alias for `unauth` + `invalid-token` |
| `passive` | Passive scan only, no active scan |
| `fuzz` | All injection rules at **Insane** strength — more payloads per rule, significantly slower |
| `session` | Session management: token-after-logout, concurrent sessions, JWT signature tamper |

Rule tests (`xss`, `sqli`, etc.) default to admin + customer phases. Add a phase name to restrict scope: `-Tests "xss,admin"`.

`fuzz` can be combined with specific rule categories or phases: `-Tests "fuzz,sqli"` runs SQLi at Insane strength; `-Tests "fuzz,admin"` runs all injection rules at Insane strength on the admin phase only.

### Scan visibility

**Real-time progress** is printed to the console every 30 seconds throughout the scan — no extra flags needed:

```
[14:32:15] -- Scan progress: admin (phase 1 of 3) --
           Progress : [==============------] 72%
           Alerts   : High=3  Medium=8  Low=5  Info=0
           Running  : SQL Injection (45 req) [2 alerts]  |  Path Traversal (12 req)
           Requests : 312 total (6 new)
             [200] POST /rest/user/login
             [500] GET  /rest/products/search?q=1'--
             [200] GET  /api/Products/1
             [403] GET  /rest/user/whoami
             [200] PUT  /api/BasketItems/1
             [404] GET  /rest/admin/application-configuration
```

HTTP lines are color-coded: green = 2xx, cyan = 3xx, yellow = 4xx, red = 5xx. Up to 8 new requests are shown per poll.

**Session save** — add `-SaveSession` to preserve the full ZAP session for inspection in the GUI:

```powershell
.\projects\juice-shop\scripts\run-scan.ps1 -Env dev -SaveSession
```

This saves `reports/sessions/juice-shop-<timestamp>.session`. After the scan, open it in ZAP desktop via **File → Open Session** to browse every request, response, and alert in detail.

Reports are saved to `reports/`:

| File | Description |
|------|-------------|
| `zap-report-juice-shop-<timestamp>.json` | Raw ZAP findings (machine-readable) |
| `zap-report-juice-shop-<timestamp>.html` | ZAP default HTML report |
| `zap-report-juice-shop-<timestamp>.clean.html` | Clean report with risk cards, CWE/WASC links, and a reading guide — generated automatically by `generate-report.ps1` |
| `sessions/juice-shop-<timestamp>.session` | ZAP session file — only written when `-SaveSession` is used |

Open the `.clean.html` file in any browser — it has no external dependencies.

## Running via GitHub Actions

Triggered manually: **Actions → ZAP Security Scan → Run workflow**

Select the project and environment, then configure the following secrets under **Settings → Secrets → Actions**:

| Secret | Description |
|--------|-------------|
| `JUICE_SHOP_ADMIN_PASSWORD` | Password for `admin@juice-sh.op` (default: `admin123`) |
| `JUICE_SHOP_CUSTOMER_PASSWORD` | Shared password for the two customer accounts |

The workflow:
1. Starts Juice Shop in Docker
2. Registers customer accounts
3. Runs rate limiting and access control checks
4. Runs the full multi-role ZAP scan with token refresh
5. Uploads HTML/JSON reports as artifacts
6. Uploads a SARIF report to the **GitHub Security tab**
7. Opens a GitHub Issue automatically if any High or Critical alerts are found

## Scan policies

Rules are tuned for Bearer-token-authenticated REST APIs:
- Cookie security rules disabled — APIs use `Authorization` headers, not cookies
- Browser/HTML header rules disabled — not applicable to REST APIs
- CSRF disabled — Bearer token auth already mitigates CSRF
- Cache-control threshold lowered — noisy for REST APIs

The effective rules are inlined in each project's `automation.yaml`. `common/scan-policies/rest-api.xml` is the equivalent policy for import into ZAP desktop.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidance on tuning rules or adding projects.
