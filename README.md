# owasp-zap-multirole-scanner

OWASP ZAP automated security testing for REST APIs. Uses the [ZAP Automation Framework](https://www.zaproxy.org/docs/automate/automation-framework/) to run multi-phase active scans across different authentication roles, with token refresh, access control checks, and SARIF output for the GitHub Security tab.

Targets [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) — a deliberately vulnerable web application designed for security testing practice.

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
      openapi.json               # OpenAPI spec (gitignored, fetched before running)
    scripts/
      run-scan.ps1               # Local scan runner (Windows/PowerShell)
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

# 2. Fetch the OpenAPI spec
Invoke-WebRequest http://localhost:3000/api-docs -OutFile projects/juice-shop/specs/openapi.json

# 3. Register customer accounts (first run only)
#    See CONTRIBUTING.md for the registration commands

# 4. Set required environment variables
$env:JUICE_SHOP_ADMIN_PASSWORD    = "admin123"
$env:JUICE_SHOP_CUSTOMER_PASSWORD = "YourCustomerPassword"

# 5. Run the scan
.\projects\juice-shop\scripts\run-scan.ps1 -Env dev
```

Reports are saved to `reports/zap-report-juice-shop-<timestamp>.html` and `.json`.

## Running via GitHub Actions

Triggered manually: **Actions → ZAP Security Scan → Run workflow**

Select the project and environment, then configure the following secrets under **Settings → Secrets → Actions**:

| Secret | Description |
|--------|-------------|
| `JUICE_SHOP_ADMIN_PASSWORD` | Password for `admin@juice-sh.op` (default: `admin123`) |
| `JUICE_SHOP_CUSTOMER_PASSWORD` | Shared password for the two customer accounts |

The workflow:
1. Starts Juice Shop in Docker
2. Fetches the OpenAPI spec
3. Registers customer accounts
4. Runs rate limiting and access control checks
5. Runs the full multi-role ZAP scan with token refresh
6. Uploads HTML/JSON reports as artifacts
7. Uploads a SARIF report to the **GitHub Security tab**
8. Opens a GitHub Issue automatically if any High or Critical alerts are found

## Scan policies

Rules are tuned for Bearer-token-authenticated REST APIs:
- Cookie security rules disabled — APIs use `Authorization` headers, not cookies
- Browser/HTML header rules disabled — not applicable to REST APIs
- CSRF disabled — Bearer token auth already mitigates CSRF
- Cache-control threshold lowered — noisy for REST APIs

The effective rules are inlined in each project's `automation.yaml`. `common/scan-policies/rest-api.xml` is the equivalent policy for import into ZAP desktop.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidance on tuning rules or adding projects.
