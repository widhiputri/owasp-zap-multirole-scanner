# ZAP Security Scan Runner - Juice Shop
#
# Runs a selective or full multi-role ZAP scan. Use -Tests to run only
# specific checks. Token refresh and phase detection adapt automatically
# to whichever subset of phases is enabled.
#
# Usage:
#   .\run-scan.ps1 -Env dev                             # full scan (default)
#   .\run-scan.ps1 -Env dev -Tests "bola"               # access control check only
#   .\run-scan.ps1 -Env dev -Tests "xss,sqli"           # XSS + SQLi across admin/customer
#   .\run-scan.ps1 -Env dev -Tests "xss,admin"          # XSS on admin phase only
#   .\run-scan.ps1 -Env dev -Tests "auth-bypass"        # unauth + invalid-token phases
#   .\run-scan.ps1 -Env dev -Tests "passive"            # passive scan only
#   .\run-scan.ps1 -Env dev -SaveSession                # also save .session file for ZAP GUI
#
# Available test names (combine with commas):
#
#   all            Run everything - default
#
#   Pre-scan checks (no ZAP required):
#   bola           BOLA / cross-role / cross-customer access control check
#   rate-limit     Auth endpoint rate limiting probe (20 rapid requests)
#
#   ZAP rule categories (run across admin+customer phases by default):
#   xss            Cross-site scripting
#   sqli           SQL injection
#   path-traversal Path traversal
#   cmd-injection  OS command injection
#   ssrf           Server-side request forgery
#   xxe            XML external entity injection
#   ldap           LDAP injection
#
#   ZAP scan phases (combine with rule categories to restrict scope):
#   admin          Admin-role active scan (all rules unless rule category specified)
#   customer       Customer-role active scan
#   unauth         Unauthenticated active scan
#   invalid-token  Invalid/expired token active scan
#   auth-bypass    Alias for unauth + invalid-token
#   passive        Passive scan only (no active scan)
#
# Auth follows the Resource Owner Password Credentials pattern:
#   POST /rest/user/login { email, password } -> { authentication.token }
#
# Requirements:
#   - OWASP ZAP installed at default location
#   - docker compose up -d  (Juice Shop running)
#   - Env vars: JUICE_SHOP_ADMIN_PASSWORD, JUICE_SHOP_CUSTOMER_PASSWORD
#   - Customer accounts pre-registered (see CONTRIBUTING.md)

param (
    [Parameter(Mandatory=$true)]
    [string]$Env,

    [string]$Tests = "all",

    # Save ZAP session to reports/sessions/ so it can be opened in ZAP GUI later.
    # File: reports/sessions/juice-shop-<timestamp>.session
    # Open via: ZAP > File > Open Session
    [switch]$SaveSession
)

$ZAP_DIR     = "C:\Program Files\ZAP\Zed Attack Proxy"
$ZAP_PATH    = "$ZAP_DIR\zap.bat"
$ZAP_PORT    = 8080
$ZAP_KEY     = "zapkey"
$ZAP_BASE    = "http://localhost:$ZAP_PORT"
$PROJECT_DIR = Split-Path -Parent $PSScriptRoot
$CONFIG_FILE = "$PROJECT_DIR\config\$Env.properties"
$TEMP_PLAN   = "$PROJECT_DIR\automation.tmp.yaml"

# Load config
Write-Host "[*] Loading config: $CONFIG_FILE"
$config = @{}
Get-Content $CONFIG_FILE | ForEach-Object {
    if ($_ -match "^\s*([^#][^=]+)=(.*)$") {
        $config[$matches[1].Trim()] = $matches[2].Trim()
    }
}
$base_url           = $config["base_url"]
$admin_username     = $config["admin_username"]
$customer_username  = $config["customer_username"]
$customer2_username = $config["customer2_username"]
$admin_password     = $env:JUICE_SHOP_ADMIN_PASSWORD
$customer_password  = $env:JUICE_SHOP_CUSTOMER_PASSWORD

# =============================================================================
# Test selection
# =============================================================================

$validTests = @(
    "all",
    "bola", "rate-limit",
    "xss", "sqli", "path-traversal", "cmd-injection", "ssrf", "xxe", "ldap",
    "admin", "customer", "unauth", "invalid-token", "auth-bypass", "passive"
)

$testList = ($Tests.ToLower() -split '[,\s]+') | Where-Object { $_ -ne '' } | Select-Object -Unique
foreach ($t in $testList) {
    if ($validTests -notcontains $t) {
        Write-Error "Unknown test '$t'. Valid values: $($validTests -join ', ')"
        exit 1
    }
}

$runAll = $testList -contains "all"
function Should-Run([string]$name) { $runAll -or ($testList -contains $name) }

# ZAP rule category -> scan rule IDs
$ruleCategories = @{
    "xss" = @(
        [pscustomobject]@{ id = 40012; name = "Cross Site Scripting (Reflected)" }
        [pscustomobject]@{ id = 40014; name = "Cross Site Scripting (Persistent)" }
        [pscustomobject]@{ id = 40016; name = "Cross Site Scripting (Persistent) - Prime" }
        [pscustomobject]@{ id = 40017; name = "Cross Site Scripting (Persistent) - Spider" }
        [pscustomobject]@{ id = 40026; name = "Cross Site Scripting (DOM Based)" }
    )
    "sqli" = @(
        [pscustomobject]@{ id = 40018; name = "SQL Injection" }
        [pscustomobject]@{ id = 40019; name = "SQL Injection - MySQL" }
        [pscustomobject]@{ id = 40020; name = "SQL Injection - Hypersonic SQL" }
        [pscustomobject]@{ id = 40021; name = "SQL Injection - Oracle" }
        [pscustomobject]@{ id = 40022; name = "SQL Injection - PostgreSQL" }
        [pscustomobject]@{ id = 40024; name = "SQL Injection - SQLite" }
    )
    "path-traversal" = @(
        [pscustomobject]@{ id = 6; name = "Path Traversal" }
    )
    "cmd-injection" = @(
        [pscustomobject]@{ id = 90020; name = "Remote OS Command Injection" }
        [pscustomobject]@{ id = 40032; name = "OS Command Injection (External)" }
    )
    "ssrf" = @(
        [pscustomobject]@{ id = 40046; name = "SSRF" }
    )
    "xxe" = @(
        [pscustomobject]@{ id = 90023; name = "XML External Entity Attack" }
    )
    "ldap" = @(
        [pscustomobject]@{ id = 40015; name = "LDAP Injection" }
    )
}

$ruleCatNames = @("xss","sqli","path-traversal","cmd-injection","ssrf","xxe","ldap")
$phaseNames   = @("admin","customer","unauth","invalid-token","auth-bypass","passive")

$hasRuleCat = ($testList | Where-Object { $ruleCatNames -contains $_ }).Count -gt 0
$hasPhase   = ($testList | Where-Object { $phaseNames   -contains $_ }).Count -gt 0

# Determine which ZAP phases to run
if ($runAll) {
    $runAdmin    = $true
    $runCustomer = $true
    $runUnauth   = $true
    $runInvalid  = $true
} elseif ($hasRuleCat -and -not $hasPhase) {
    # Rule categories without explicit phase -> default to admin + customer
    $runAdmin    = $true
    $runCustomer = $true
    $runUnauth   = $false
    $runInvalid  = $false
} else {
    $runAdmin    = Should-Run "admin"
    $runCustomer = Should-Run "customer"
    $runUnauth   = (Should-Run "unauth") -or (Should-Run "auth-bypass")
    $runInvalid  = (Should-Run "invalid-token") -or (Should-Run "auth-bypass")
}

# passive = passive scan only; ignored if active phases are also selected
$passiveOnly = (Should-Run "passive") -and -not ($runAdmin -or $runCustomer -or $runUnauth -or $runInvalid)

# Collect filtered rules (empty array = use all rules)
$filteredRules = @()
if (-not $runAll) {
    foreach ($cat in $ruleCatNames) {
        if (Should-Run $cat) { $filteredRules += $ruleCategories[$cat] }
    }
}

$checkBola      = Should-Run "bola"
$checkRateLimit = Should-Run "rate-limit"
$needsZap       = $runAdmin -or $runCustomer -or $runUnauth -or $runInvalid -or $passiveOnly

# Active scan phase sequence (index = ZAP scan ID assigned by automation plan)
$activeScanSeq = @()
if ($runAdmin)    { $activeScanSeq += "admin" }
if ($runCustomer) { $activeScanSeq += "customer" }
if ($runUnauth)   { $activeScanSeq += "unauth" }
if ($runInvalid)  { $activeScanSeq += "invalid-token" }

# Print run plan
Write-Host ""
Write-Host "[*] Run plan: -Env $Env -Tests '$Tests'"
if ($checkRateLimit) { Write-Host "    rate-limit    : auth endpoint probe (20 requests)" }
if ($checkBola)      { Write-Host "    bola          : cross-role + cross-customer checks" }
if ($passiveOnly)    { Write-Host "    passive       : passive scan only" }
foreach ($ph in $activeScanSeq) {
    if ($filteredRules.Count -gt 0) {
        $ruleList = ($filteredRules | ForEach-Object { $_.name }) -join ", "
        Write-Host "    $ph : active scan  rules: $ruleList"
    } else {
        Write-Host "    $ph : active scan  all rules"
    }
}
if (-not $checkBola -and -not $checkRateLimit -and -not $needsZap) {
    Write-Warning "Nothing to run. Use -Tests all or specify at least one test name."
    exit 0
}
Write-Host ""

# Credentials check
$needsCreds = $checkBola -or $runAdmin -or $runCustomer
if ($needsCreds -and (-not $admin_password -or -not $customer_password)) {
    Write-Error "Missing required env vars: JUICE_SHOP_ADMIN_PASSWORD, JUICE_SHOP_CUSTOMER_PASSWORD"
    exit 1
}

# =============================================================================
# Helper functions
# =============================================================================

function Get-Token($username, $password) {
    $body = @{ email = $username; password = $password } | ConvertTo-Json
    Write-Host "[*] Fetching token for: $username"
    try {
        $response = Invoke-RestMethod -Method Post -Uri "$base_url/rest/user/login" `
            -ContentType "application/json" -Body $body
        return $response.authentication.token
    } catch {
        Write-Error "Failed to get token for $username : $_"
        exit 1
    }
}

function Invoke-ZapApi($path, $params = @{}) {
    $headers = @{ "X-ZAP-API-Key" = $ZAP_KEY }
    $uri = "$ZAP_BASE$path"
    if ($params.Count -gt 0) {
        $query = ($params.GetEnumerator() | ForEach-Object {
            "$($_.Key)=$([System.Uri]::EscapeDataString($_.Value))"
        }) -join "&"
        $uri = "$uri`?$query"
    }
    return Invoke-RestMethod -Uri $uri -Headers $headers -Method Get
}

function Set-ZapReplacerRule($description, $token) {
    try { Invoke-ZapApi "/JSON/replacer/action/removeRule/" @{ description = $description } | Out-Null } catch {}
    Invoke-ZapApi "/JSON/replacer/action/addRule/" @{
        description = $description
        enabled     = "true"
        matchType   = "REQ_HEADER"
        matchRegex  = "false"
        matchString = "Authorization"
        replacement = "Bearer $token"
        initiators  = ""
    } | Out-Null
    Write-Host "[*] [$(Get-Date -Format 'HH:mm:ss')] Replacer updated: $description"
}

function Wait-ForZap {
    Write-Host "[*] Waiting for ZAP to be ready..."
    for ($i = 0; $i -lt 60; $i++) {
        try {
            Invoke-ZapApi "/JSON/core/view/version/" | Out-Null
            Write-Host "[*] ZAP is ready."
            return $true
        } catch { Start-Sleep 3 }
    }
    Write-Error "ZAP did not become ready after 3 minutes."
    return $false
}

# Print a live progress block for the active scan currently running.
# Called every polling interval so the user can see what ZAP is doing without
# opening the GUI. Shows scan %, alert counts by severity, and active rules.
function Show-ScanProgress($phaseIdx, $phaseSeq) {
    if ($phaseSeq.Count -eq 0 -or $phaseIdx -ge $phaseSeq.Count) { return }

    $phase  = $phaseSeq[$phaseIdx]
    $scanId = [string]$phaseIdx
    $ts     = Get-Date -Format 'HH:mm:ss'

    try {
        # Overall scan percentage
        $s      = Invoke-ZapApi "/JSON/ascan/view/status/" @{ scanId = $scanId }
        $pct    = [int]$s.status
        $filled = [int]($pct / 5)
        $bar    = ("=" * $filled) + ("-" * (20 - $filled))

        Write-Host ""
        Write-Host "[$ts] -- Scan progress: $phase (phase $($phaseIdx+1) of $($phaseSeq.Count)) --"
        Write-Host "           Progress : [$bar] $pct%"

        # Alert counts by severity
        try {
            $sum = Invoke-ZapApi "/JSON/alert/view/alertsSummary/"
            $as  = $sum.alertsSummary
            Write-Host "           Alerts   : High=$($as.High)  Medium=$($as.Medium)  Low=$($as.Low)  Info=$($as.Informational)"
        } catch {
            try {
                $n = Invoke-ZapApi "/JSON/core/view/numberOfAlerts/"
                Write-Host "           Alerts   : $($n.numberOfAlerts) total"
            } catch {}
        }

        # Currently active scan rules from scanProgress API
        try {
            $prog       = Invoke-ZapApi "/JSON/ascan/view/scanProgress/" @{ scanId = $scanId }
            $allPlugins = @()
            foreach ($entry in $prog.scanProgress) {
                $hostProcs = if ($entry.HostProcess) { @($entry.HostProcess) } else { @() }
                foreach ($hp in $hostProcs) {
                    $allPlugins += if ($hp.Plugin) { @($hp.Plugin) } else { @() }
                }
            }
            $running = @($allPlugins | Where-Object { $_.status -eq "running" })
            if ($running.Count -gt 0) {
                $names = ($running | Select-Object -First 4 | ForEach-Object {
                    $label = $_.name
                    if ($_.requestCount) { $label += " ($($_.requestCount) req)" }
                    if ($_.alertCount -and [int]$_.alertCount -gt 0) { $label += " [$($_.alertCount) alerts]" }
                    $label
                }) -join "  |  "
                Write-Host "           Running  : $names"
            } else {
                $done = ($allPlugins | Where-Object { $_.status -ne $null }).Count
                if ($done -gt 0) { Write-Host "           Rules    : $done completed, waiting for next..." }
            }
        } catch {}

    } catch {}
}

# Print progress for passive-only runs (no activeScan API available).
function Show-PassiveProgress {
    try {
        $rec = Invoke-ZapApi "/JSON/pscan/view/recordsToScan/"
        $ts  = Get-Date -Format 'HH:mm:ss'
        Write-Host "[$ts] -- Passive scan: $($rec.recordsToScan) records remaining --"
    } catch {}
}

# Probe auth endpoint for rate limiting.
# Sends 20 rapid login requests; warns if no 429 is returned.
function Test-RateLimiting {
    Write-Host "[*] Probing auth endpoint for rate limiting..."
    $url  = "$base_url/rest/user/login"
    $body = @{ email = "nonexistent@shopsafe.io"; password = "wrongpassword" } | ConvertTo-Json
    $rateLimited = $false
    for ($i = 1; $i -le 20; $i++) {
        try {
            $resp = Invoke-WebRequest -Method Post -Uri $url `
                -ContentType "application/json" -Body $body `
                -SkipHttpErrorCheck -UseBasicParsing
            if ($resp.StatusCode -eq 429) {
                Write-Host "[*] Rate limit detected after $i requests (429 Too Many Requests). PASS."
                $rateLimited = $true
                break
            }
        } catch {}
    }
    if (-not $rateLimited) {
        Write-Warning "[!] No rate limiting detected after 20 rapid auth requests. Consider adding rate limiting to the auth endpoint."
    }
}

# Cross-role: customer token must not access admin-only endpoints.
# Cross-customer: customer1 token must not access customer2's basket/orders.
function Test-AccessControls($adminToken, $customerToken, $customer2Token) {
    Write-Host "[*] Running access control checks..."
    $failed = $false

    $crossRoleChecks = @(
        @{ desc = "GET /api/Users (admin-only)";      url = "$base_url/api/Users" }
        @{ desc = "GET /api/Challenges (admin-only)"; url = "$base_url/api/Challenges" }
        @{ desc = "GET /api/Complaints (admin-only)"; url = "$base_url/api/Complaints" }
        @{ desc = "GET /api/Recycles (admin-only)";   url = "$base_url/api/Recycles" }
    )
    foreach ($check in $crossRoleChecks) {
        try {
            $resp = Invoke-WebRequest -Uri $check.url `
                -Headers @{ Authorization = "Bearer $customerToken" } -UseBasicParsing
            if ($resp.StatusCode -eq 200) {
                Write-Warning "[!] BOLA FAIL (cross-role): $($check.desc) returned 200 with customer token"
                $failed = $true
            } else {
                Write-Host "[*] BOLA PASS (cross-role): $($check.desc) -> $($resp.StatusCode)"
            }
        } catch [System.Net.WebException] {
            $statusCode = [int]$_.Exception.Response.StatusCode
            Write-Host "[*] BOLA PASS (cross-role): $($check.desc) -> $statusCode"
        } catch {
            Write-Host "[*] BOLA PASS (network error): $($check.desc)"
        }
    }

    $crossCustomerChecks = @(
        @{ desc = "GET /rest/basket/2 (customer2 basket)";       url = "$base_url/rest/basket/2" }
        @{ desc = "GET /api/Orders?userId=2 (customer2 orders)"; url = "$base_url/api/Orders?userId=2" }
    )
    foreach ($check in $crossCustomerChecks) {
        try {
            $resp = Invoke-WebRequest -Uri $check.url `
                -Headers @{ Authorization = "Bearer $customerToken" } -UseBasicParsing
            if ($resp.StatusCode -eq 200) {
                Write-Warning "[!] BOLA FAIL (cross-customer): $($check.desc) returned 200 with customer1 token"
                $failed = $true
            } else {
                Write-Host "[*] BOLA PASS (cross-customer): $($check.desc) -> $($resp.StatusCode)"
            }
        } catch [System.Net.WebException] {
            $statusCode = [int]$_.Exception.Response.StatusCode
            Write-Host "[*] BOLA PASS (cross-customer): $($check.desc) -> $statusCode"
        } catch {
            Write-Host "[*] BOLA PASS (network error): $($check.desc)"
        }
    }

    if ($failed) {
        Write-Warning "[!] Access control issues found -- review warnings above before proceeding."
    } else {
        Write-Host "[*] All access control checks passed."
    }
}

# =============================================================================
# Automation plan generator
# =============================================================================
#
# Builds the ZAP automation YAML dynamically based on the selected phases and
# rule filter. The static automation.yaml in the project root documents the
# full default configuration for reference.

function Build-AutomationYaml {
    param(
        [string]$BaseUrl,
        [string]$AdminToken,
        [string]$CustomerToken,
        [string]$ReportTimestamp,
        [bool]$RunAdmin,
        [bool]$RunCustomer,
        [bool]$RunUnauth,
        [bool]$RunInvalidToken,
        [bool]$PassiveOnly,
        [array]$FilteredRules
    )

    # Build the policyDefinition block shared by all activeScan jobs.
    # When FilteredRules is populated: set defaultThreshold Off, enable only listed rules.
    # When empty: use standard Medium threshold (all rules active).
    function Get-PolicyBlock {
        if ($FilteredRules -and $FilteredRules.Count -gt 0) {
            $ruleLines = ($FilteredRules | ForEach-Object {
                "      - id: $($_.id)`n        name: `"$($_.name)`"`n        threshold: Medium`n        strength: Medium"
            }) -join "`n"
            return "    policyDefinition:`n      defaultStrength: Medium`n      defaultThreshold: Off`n      rules:`n$ruleLines"
        }
        return "    policyDefinition:`n      defaultStrength: Medium`n      defaultThreshold: Medium"
    }

    $policy = Get-PolicyBlock
    $L = [System.Collections.Generic.List[string]]::new()

    # --- env block ---
    $L.Add("---")
    $L.Add("env:")
    $L.Add("  contexts:")
    $L.Add("    - name: juice-shop")
    $L.Add("      urls:")
    $L.Add("        - `"$BaseUrl`"")
    $L.Add("      includePaths:")
    $L.Add("        - `"$BaseUrl/api/.*`"")
    $L.Add("        - `"$BaseUrl/rest/.*`"")
    $L.Add("")
    $L.Add("  parameters:")
    $L.Add("    failOnError: true")
    $L.Add("    failOnWarning: false")
    $L.Add("    progressToStdout: true")
    $L.Add("")
    $L.Add("  vars:")
    $L.Add("    base_url: `"`"")
    $L.Add("    admin_token: `"`"")
    $L.Add("    customer_token: `"`"")
    $L.Add("    report_timestamp: `"`"")
    $L.Add("")
    $L.Add("jobs:")

    # --- passive scan config (always) ---
    $L.Add("  - type: passiveScan-config")
    $L.Add("    name: passiveScan-config")
    $L.Add("    parameters:")
    $L.Add("      maxAlertsPerRule: 10")
    $L.Add("      scanOnlyInScope: true")
    $L.Add("    rules:")
    $L.Add("      # Cookie security: APIs use Authorization headers, not cookies")
    $L.Add("      - id: 10010")
    $L.Add("        name: `"Cookie No HttpOnly Flag`"")
    $L.Add("        threshold: off")
    $L.Add("      - id: 10011")
    $L.Add("        name: `"Cookie Without Secure Flag`"")
    $L.Add("        threshold: off")
    $L.Add("      - id: 10054")
    $L.Add("        name: `"Cookie Without SameSite Attribute`"")
    $L.Add("        threshold: off")
    $L.Add("      # Browser/HTML headers: not applicable to REST APIs")
    $L.Add("      - id: 10020")
    $L.Add("        name: `"Anti-clickjacking Header`"")
    $L.Add("        threshold: off")
    $L.Add("      - id: 10038")
    $L.Add("        name: `"Content Security Policy Header Not Set`"")
    $L.Add("        threshold: off")
    $L.Add("      - id: 10055")
    $L.Add("        name: `"CSP Scanner`"")
    $L.Add("        threshold: off")
    $L.Add("      - id: 10040")
    $L.Add("        name: `"Secure Pages Include Mixed Content`"")
    $L.Add("        threshold: off")
    $L.Add("      - id: 10017")
    $L.Add("        name: `"Cross-Domain JavaScript Source File Inclusion`"")
    $L.Add("        threshold: off")
    $L.Add("      # Cache-control: lower threshold for REST APIs")
    $L.Add("      - id: 10015")
    $L.Add("        name: `"Incomplete or No Cache-control Header Set`"")
    $L.Add("        threshold: low")

    # --- initial token replacer ---
    # Inject the first authenticated phase's token before the OpenAPI import so
    # the passive scan and first active scan start with the right context.
    if ($RunAdmin) {
        $L.Add("  - type: replacer")
        $L.Add("    name: set-admin-token")
        $L.Add("    parameters:")
        $L.Add("      deleteAllRules: true")
        $L.Add("    rules:")
        $L.Add("      - description: `"Inject admin Bearer token`"")
        $L.Add("        matchType: req_header")
        $L.Add("        matchString: `"Authorization`"")
        $L.Add("        matchRegex: false")
        $L.Add("        replacementString: `"Bearer $AdminToken`"")
    } elseif ($RunCustomer) {
        $L.Add("  - type: replacer")
        $L.Add("    name: set-customer-token")
        $L.Add("    parameters:")
        $L.Add("      deleteAllRules: true")
        $L.Add("    rules:")
        $L.Add("      - description: `"Inject customer Bearer token`"")
        $L.Add("        matchType: req_header")
        $L.Add("        matchString: `"Authorization`"")
        $L.Add("        matchRegex: false")
        $L.Add("        replacementString: `"Bearer $CustomerToken`"")
    }

    # --- OpenAPI import (always) ---
    $L.Add("  - type: openapi")
    $L.Add("    name: import-openapi-spec")
    $L.Add("    parameters:")
    $L.Add("      apiFile: `"specs/openapi.json`"")
    $L.Add("      context: juice-shop")
    $L.Add("      targetUrl: `"$BaseUrl`"")

    # --- passive scan wait (always) ---
    $L.Add("  - type: passiveScan-wait")
    $L.Add("    name: passiveScan-wait")
    $L.Add("    parameters:")
    $L.Add("      maxDuration: 5")

    # --- active scan jobs ---
    if (-not $PassiveOnly) {
        if ($RunAdmin) {
            $L.Add("  - type: activeScan")
            $L.Add("    name: activeScan-admin")
            $L.Add("    parameters:")
            $L.Add("      context: juice-shop")
            $L.Add("      maxScanDurationInMins: 20")
            foreach ($line in ($policy -split "`n")) { $L.Add($line) }
        }

        if ($RunCustomer) {
            $L.Add("  - type: activeScan")
            $L.Add("    name: activeScan-customer")
            $L.Add("    parameters:")
            $L.Add("      context: juice-shop")
            $L.Add("      maxScanDurationInMins: 20")
            foreach ($line in ($policy -split "`n")) { $L.Add($line) }
        }

        if ($RunUnauth -or $RunInvalidToken) {
            $L.Add("  - type: replacer")
            $L.Add("    name: set-no-token")
            $L.Add("    parameters:")
            $L.Add("      deleteAllRules: true")
            $L.Add("    rules: []")
        }

        if ($RunUnauth) {
            $L.Add("  - type: activeScan")
            $L.Add("    name: activeScan-unauthenticated")
            $L.Add("    parameters:")
            $L.Add("      context: juice-shop")
            $L.Add("      maxScanDurationInMins: 20")
            foreach ($line in ($policy -split "`n")) { $L.Add($line) }
        }

        if ($RunInvalidToken) {
            $L.Add("  - type: replacer")
            $L.Add("    name: set-invalid-token")
            $L.Add("    parameters:")
            $L.Add("      deleteAllRules: true")
            $L.Add("    rules:")
            $L.Add("      - description: `"Inject invalid Bearer token`"")
            $L.Add("        matchType: req_header")
            $L.Add("        matchString: `"Authorization`"")
            $L.Add("        matchRegex: false")
            $L.Add("        replacementString: `"Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ6YXAtdGVzdCIsImV4cCI6MX0.INVALIDSIGNATURE`"")

            $L.Add("  - type: activeScan")
            $L.Add("    name: activeScan-invalid-token")
            $L.Add("    parameters:")
            $L.Add("      context: juice-shop")
            $L.Add("      maxScanDurationInMins: 10")
            foreach ($line in ($policy -split "`n")) { $L.Add($line) }
        }
    }

    # --- alert filters (always) ---
    $L.Add("  - type: alertFilter")
    $L.Add("    name: alert-filters")
    $L.Add("    alertFilters:")
    $L.Add("      # HSTS not set: informational for local dev targets")
    $L.Add("      - ruleId: 10004")
    $L.Add("        newRisk: `"False Positive`"")
    $L.Add("      # Sensitive data in URL: IDs in REST paths are by design")
    $L.Add("      - ruleId: 10024")
    $L.Add("        newRisk: `"False Positive`"")
    $L.Add("      # Server leaks version via X-Powered-By: known for Juice Shop")
    $L.Add("      - ruleId: 10037")
    $L.Add("        newRisk: `"Info`"")

    # --- reports (always) ---
    foreach ($rpt in @(
        [pscustomobject]@{ name = "report-html";  template = "traditional-html";  file = "zap-report-juice-shop-$ReportTimestamp" }
        [pscustomobject]@{ name = "report-json";  template = "traditional-json";  file = "zap-report-juice-shop-$ReportTimestamp" }
        [pscustomobject]@{ name = "report-sarif"; template = "sarif-json";         file = "zap-report-juice-shop-$ReportTimestamp.sarif" }
    )) {
        $L.Add("  - type: report")
        $L.Add("    name: $($rpt.name)")
        $L.Add("    parameters:")
        $L.Add("      template: $($rpt.template)")
        $L.Add("      reportDir: `"../../reports`"")
        $L.Add("      reportFile: `"$($rpt.file)`"")
        $L.Add("      reportTitle: `"Juice Shop API Security Scan`"")
        $L.Add("      reportDescription: `"OWASP ZAP - Juice Shop REST API`"")
    }

    return ($L -join "`n")
}

# =============================================================================
# Token acquisition
# =============================================================================

$admin_token     = $null
$customer_token  = $null
$customer2_token = $null

if ($runAdmin -or $checkBola) {
    $admin_token = Get-Token $admin_username $admin_password
}
if ($runAdmin -or $runCustomer -or $checkBola) {
    $customer_token = Get-Token $customer_username $customer_password
}
if ($checkBola) {
    $customer2_token = Get-Token $customer2_username $customer_password
}

if (($runAdmin -or $checkBola) -and -not $admin_token) {
    Write-Error "Failed to retrieve admin token."
    exit 1
}
if (($runCustomer -or $checkBola) -and -not $customer_token) {
    Write-Error "Failed to retrieve customer token."
    exit 1
}
if ($admin_token -or $customer_token) { Write-Host "[*] Token(s) acquired." }

# =============================================================================
# Pre-scan checks
# =============================================================================

if ($checkRateLimit) { Test-RateLimiting }
if ($checkBola)      { Test-AccessControls $admin_token $customer_token $customer2_token }

if (-not $needsZap) {
    Write-Host "[*] Done."
    exit 0
}

# =============================================================================
# Generate automation plan
# =============================================================================

$report_timestamp = Get-Date -Format "yyyyMMdd-HHmm"
Write-Host "[*] Generating automation plan (report: zap-report-juice-shop-$report_timestamp)..."

$adminTokenArg    = if ($admin_token)    { $admin_token }    else { "" }
$customerTokenArg = if ($customer_token) { $customer_token } else { "" }

$planContent = Build-AutomationYaml `
    -BaseUrl         $base_url `
    -AdminToken      $adminTokenArg `
    -CustomerToken   $customerTokenArg `
    -ReportTimestamp $report_timestamp `
    -RunAdmin        $runAdmin `
    -RunCustomer     $runCustomer `
    -RunUnauth       $runUnauth `
    -RunInvalidToken $runInvalid `
    -PassiveOnly     $passiveOnly `
    -FilteredRules   $filteredRules

[System.IO.File]::WriteAllText($TEMP_PLAN, $planContent, [System.Text.UTF8Encoding]::new($false))

# Session file path (used if -SaveSession is set)
$sessionFile = $null
if ($SaveSession) {
    $sessionDir  = [System.IO.Path]::GetFullPath("$PROJECT_DIR\..\..\reports\sessions")
    New-Item -ItemType Directory -Path $sessionDir -Force | Out-Null
    $sessionFile = "$sessionDir\juice-shop-$report_timestamp"
    Write-Host "[*] Session will be saved: $sessionFile.session"
    Write-Host "    Open in ZAP GUI: File -> Open Session -> select the .session file"
}

# =============================================================================
# Shut down any existing ZAP instance
# =============================================================================

try {
    Invoke-ZapApi "/JSON/core/action/shutdown/" | Out-Null
    Write-Host "[*] Existing ZAP instance shut down. Waiting for it to exit..."
    Start-Sleep 5
} catch {}

# =============================================================================
# Start ZAP
# =============================================================================

Write-Host "[*] Starting ZAP scan on port $ZAP_PORT..."
Push-Location $ZAP_DIR
$zapArgs = "-cmd -autorun `"$TEMP_PLAN`" -port $ZAP_PORT -config api.key=$ZAP_KEY"
if ($sessionFile) { $zapArgs += " -newsession `"$sessionFile`"" }
$zapProcess = Start-Process -FilePath $ZAP_PATH `
    -ArgumentList $zapArgs `
    -PassThru -NoNewWindow
Pop-Location

if (-not (Wait-ForZap)) {
    $zapProcess | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item $TEMP_PLAN -ErrorAction SilentlyContinue
    exit 1
}

# =============================================================================
# Token refresh loop
# =============================================================================
#
# Polls ZAP every 30 seconds. Tracks which active scan phase is running,
# refreshes tokens before they expire (every 12 min), and switches the
# replacer rule when transitioning from admin to customer phase.

try {
    if ($activeScanSeq.Count -gt 0) {
        Write-Host "[*] Token refresh active (every 12 min). Phases: $($activeScanSeq -join ' -> ')"
    }
    Write-Host ""

    $currentPhaseIdx     = 0
    $tokenFetchTime      = Get-Date
    $cachedCustomerToken = $customer_token

    while (-not $zapProcess.HasExited) {
        Start-Sleep 30
        if ($zapProcess.HasExited) { break }

        # No active scan phases (passive-only run) -> show passive progress and wait
        if ($activeScanSeq.Count -eq 0) { Show-PassiveProgress; continue }

        # All phases accounted for -> just wait for ZAP to finish reporting
        if ($currentPhaseIdx -ge $activeScanSeq.Count) { continue }

        $currentPhase  = $activeScanSeq[$currentPhaseIdx]
        $currentScanId = [string]$currentPhaseIdx

        # Show live progress for every phase (authenticated or not)
        Show-ScanProgress $currentPhaseIdx $activeScanSeq

        # Unauthenticated phases: no token to refresh, just track completion
        if ($currentPhase -in @("unauth", "invalid-token")) {
            try {
                $s = Invoke-ZapApi "/JSON/ascan/view/status/" @{ scanId = $currentScanId }
                if ($s.status -eq "100") {
                    Write-Host "[*] $currentPhase scan complete."
                    $currentPhaseIdx++
                }
            } catch {}
            continue
        }

        # Authenticated phase: check for completion and handle transition
        try {
            $s = Invoke-ZapApi "/JSON/ascan/view/status/" @{ scanId = $currentScanId }
            if ($s.status -eq "100") {
                Write-Host "[*] $currentPhase scan complete."
                $currentPhaseIdx++

                # Switch replacer when moving admin -> customer
                if ($currentPhaseIdx -lt $activeScanSeq.Count) {
                    $nextPhase = $activeScanSeq[$currentPhaseIdx]
                    if ($nextPhase -eq "customer") {
                        Write-Host "[*] Switching to customer token..."
                        try { Invoke-ZapApi "/JSON/replacer/action/removeRule/" @{ description = "Inject admin Bearer token" } | Out-Null } catch {}
                        Set-ZapReplacerRule "Inject customer Bearer token" $cachedCustomerToken
                        $tokenFetchTime = Get-Date
                    }
                }
                continue
            }
        } catch {}

        # Token refresh every 12 minutes
        $elapsed = (Get-Date) - $tokenFetchTime
        if ($elapsed.TotalMinutes -gt 12) {
            if ($currentPhase -eq "admin") {
                Write-Host "[*] [$(Get-Date -Format 'HH:mm')] Refreshing admin token..."
                $admin_token = Get-Token $admin_username $admin_password
                Set-ZapReplacerRule "Inject admin Bearer token" $admin_token
                if ($runCustomer) {
                    $cachedCustomerToken = Get-Token $customer_username $customer_password
                    Write-Host "[*] [$(Get-Date -Format 'HH:mm')] Customer token cached."
                }
            } elseif ($currentPhase -eq "customer") {
                Write-Host "[*] [$(Get-Date -Format 'HH:mm')] Refreshing customer token..."
                $customer_token      = Get-Token $customer_username $customer_password
                $cachedCustomerToken = $customer_token
                Set-ZapReplacerRule "Inject customer Bearer token" $customer_token
            }
            $tokenFetchTime = Get-Date
        }
    }

    Write-Host ""
    Write-Host "[*] ZAP scan completed."

    # Save session via API (ensures the .session file is fully flushed to disk)
    if ($sessionFile) {
        try {
            Invoke-ZapApi "/JSON/core/action/saveSession/" @{ name = $sessionFile; overwrite = "true" } | Out-Null
            Write-Host "[*] Session saved: $sessionFile.session"
        } catch {
            Write-Host "[*] Session file: $sessionFile.session (saved via -newsession at startup)"
        }
    }

    # Generate clean HTML report from JSON output
    $reportJson     = "$PROJECT_DIR\..\..\reports\zap-report-juice-shop-$report_timestamp.json"
    $generateScript = "$PSScriptRoot\generate-report.ps1"
    if ((Test-Path $reportJson) -and (Test-Path $generateScript)) {
        & $generateScript -JsonReport $reportJson
    }

} finally {
    if (-not $zapProcess.HasExited) {
        Write-Host "[*] Stopping ZAP..."
        $zapProcess | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $TEMP_PLAN -ErrorAction SilentlyContinue
    Write-Host "[*] Temp files cleaned up."
}
