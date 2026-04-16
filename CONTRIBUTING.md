# Contributing

## OpenAPI spec

The spec at `projects/juice-shop/specs/openapi.json` is manually authored and tracked in the repo. It covers the main Juice Shop REST and ORM endpoints (`/rest/` and `/api/`). No fetch step is needed before running.

To add or remove endpoints, edit the spec directly and commit the change.

## Registering customer accounts

Juice Shop ships with a built-in admin account (`admin@juice-sh.op`). The two customer accounts used by the scanner must be registered before the first scan:

```powershell
$base = "http://localhost:3000"
$pass = "YourCustomerPassword"
$q    = @{ id = 1; question = "Your eldest sibling's middle name?" }

# customer1
Invoke-RestMethod -Method Post -Uri "$base/api/Users" -ContentType "application/json" -Body (@{
    email = "customer1@shopsafe.io"; password = $pass; passwordRepeat = $pass
    securityQuestion = $q; securityAnswer = "test"
} | ConvertTo-Json)

# customer2
Invoke-RestMethod -Method Post -Uri "$base/api/Users" -ContentType "application/json" -Body (@{
    email = "customer2@shopsafe.io"; password = $pass; passwordRepeat = $pass
    securityQuestion = $q; securityAnswer = "test"
} | ConvertTo-Json)
```

The CI workflow registers both accounts automatically before each scan.

## Adding a new environment

1. Create `projects/<project>/config/<env>.properties` based on an existing one
2. Add the new environment to the `options` list under the `environment` input in `.github/workflows/security-scan.yml`
3. Add any required secrets under **Settings → Secrets → Actions**

## Adding a new project

1. Create `projects/<project>/` (copy `juice-shop/` as a starting point)
2. Update `automation.yaml`:
   - Change the context name
   - Update `reportTitle`, `reportDescription`, and `reportFile` prefix
   - Adjust `maxScanDurationInMins` as needed
3. Add `config/<env>.properties` with the target URL and account names
4. Update `scripts/run-scan.ps1`:
   - Change the token-fetch function to match the new target's auth endpoint
   - Update BOLA checks for the new project's endpoint structure
5. Add the project to the `options` list in the workflow `project` input

## Tuning scan rules

Rules are defined inline in each `activeScan` job's `policyDefinition` block in `automation.yaml`, and mirrored in `common/scan-policies/rest-api.xml` for ZAP desktop use.

To disable a rule:
```yaml
policyDefinition:
  rules:
    - id: 10010
      name: "Cookie No HttpOnly Flag"
      threshold: Off
```

To lower the noise threshold:
```yaml
    - id: 10015
      name: "Incomplete or No Cache-control Header Set"
      threshold: Low
```

Valid threshold values: `Off`, `Low`, `Medium`, `High`
Valid strength values: `Low`, `Medium`, `High`, `Insane`

Keep `common/scan-policies/rest-api.xml` in sync with changes so ZAP desktop users get the same policy.
Import via: **Analyse → Scan Policy Manager → Import**.

To look up a rule ID: run a scan and check the report, or browse the [ZAP alert list](https://www.zaproxy.org/docs/alerts/).

## Secrets reference

| Secret | Description |
|--------|-------------|
| `JUICE_SHOP_ADMIN_PASSWORD` | Password for `admin@juice-sh.op` (default: `admin123`) |
| `JUICE_SHOP_CUSTOMER_PASSWORD` | Shared password for `customer1` and `customer2` accounts |
