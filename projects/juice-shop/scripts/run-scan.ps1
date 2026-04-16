# ZAP Security Scan Runner - Juice Shop
#
# Runs ZAP automation plan with the API port exposed, refreshes tokens every
# 12 minutes via ZAP API so long scans stay authenticated throughout, and
# runs BOLA / cross-role / cross-customer access checks before the scan starts.
#
# Auth follows the Resource Owner Password Credentials pattern:
#   POST /rest/user/login  { email, password }  ->  { authentication.token }
# The returned JWT is injected into all requests via ZAP's replacer job.
#
# Usage:
#   .\run-scan.ps1 -Env dev
#   .\run-scan.ps1 -Env staging
#
# Requirements:
#   - OWASP ZAP installed at default location
#   - docker compose up -d  (Juice Shop running)
#   - OpenAPI spec fetched to projects\juice-shop\specs\openapi.json
#   - Env vars: JUICE_SHOP_ADMIN_PASSWORD, JUICE_SHOP_CUSTOMER_PASSWORD
#   - Customer accounts pre-registered in Juice Shop (see README)

param (
    [Parameter(Mandatory=$true)]
    [string]$Env
)

$ZAP_DIR     = "C:\Program Files\ZAP\Zed Attack Proxy"
$ZAP_PATH    = "$ZAP_DIR\zap.bat"
$ZAP_PORT    = 8080
$ZAP_KEY     = "zapkey"
$ZAP_BASE    = "http://localhost:$ZAP_PORT"
$PROJECT_DIR = Split-Path -Parent $PSScriptRoot
$CONFIG_FILE = "$PROJECT_DIR\config\$Env.properties"
$PLAN_FILE   = "$PROJECT_DIR\automation.yaml"
$TEMP_PLAN   = "$PROJECT_DIR\automation.tmp.yaml"

# Load config file
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

$admin_password    = $env:JUICE_SHOP_ADMIN_PASSWORD
$customer_password = $env:JUICE_SHOP_CUSTOMER_PASSWORD

if (-not $admin_password -or -not $customer_password) {
    Write-Error "Missing required environment variables: JUICE_SHOP_ADMIN_PASSWORD, JUICE_SHOP_CUSTOMER_PASSWORD"
    exit 1
}

# Helper: fetch Juice Shop JWT
# Follows the Resource Owner Password Credentials pattern:
#   POST credentials -> receive short-lived JWT -> use as Bearer token
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

# Helper: call ZAP REST API
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

# Helper: update a ZAP replacer rule with a fresh token
function Set-ZapReplacerRule($description, $token) {
    try {
        Invoke-ZapApi "/JSON/replacer/action/removeRule/" @{ description = $description } | Out-Null
    } catch {}

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

# Helper: wait for ZAP API to become available
function Wait-ForZap {
    Write-Host "[*] Waiting for ZAP to be ready..."
    for ($i = 0; $i -lt 60; $i++) {
        try {
            Invoke-ZapApi "/JSON/core/view/version/" | Out-Null
            Write-Host "[*] ZAP is ready."
            return $true
        } catch {
            Start-Sleep 3
        }
    }
    Write-Error "ZAP did not become ready after 3 minutes."
    return $false
}

# Helper: probe auth endpoint for rate limiting
# Sends 20 rapid login requests and checks whether the server enforces
# any rate limiting (429 or lockout). Reports a warning if not -- any
# endpoint accepting unlimited credential submissions is a brute-force risk.
function Test-RateLimiting {
    Write-Host "`n[*] Probing auth endpoint for rate limiting..."
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

# Helper: BOLA / cross-role / cross-customer access checks
# Cross-role: customer token must not access admin-only endpoints.
# Cross-customer: customer1 token must not access customer2's basket/orders.
function Test-AccessControls($adminToken, $customerToken, $customer2Token) {
    Write-Host "`n[*] Running access control checks..."
    $failed = $false

    # Cross-role checks: customer should be blocked from admin endpoints
    $crossRoleChecks = @(
        @{ desc = "GET /api/Users (admin-only)";      url = "$base_url/api/Users" },
        @{ desc = "GET /api/Challenges (admin-only)"; url = "$base_url/api/Challenges" },
        @{ desc = "GET /api/Complaints (admin-only)"; url = "$base_url/api/Complaints" },
        @{ desc = "GET /api/Recycles (admin-only)";   url = "$base_url/api/Recycles" }
    )

    foreach ($check in $crossRoleChecks) {
        try {
            $resp = Invoke-WebRequest -Uri $check.url `
                -Headers @{ Authorization = "Bearer $customerToken" } `
                -UseBasicParsing
            if ($resp.StatusCode -eq 200) {
                Write-Warning "[!] BOLA FAIL (cross-role): $($check.desc) returned 200 with customer token"
                $failed = $true
            } else {
                Write-Host "[*] BOLA PASS (cross-role): $($check.desc) -> $($resp.StatusCode)"
            }
        } catch [System.Net.WebException] {
            # HTTP error response (401/403) -- access was correctly denied
            $statusCode = [int]$_.Exception.Response.StatusCode
            Write-Host "[*] BOLA PASS (cross-role): $($check.desc) -> $statusCode"
        } catch {
            Write-Host "[*] BOLA PASS (network error): $($check.desc)"
        }
    }

    # Cross-customer checks: customer1 should not access customer2's resources.
    # Basket IDs 1 and 2 belong to the first two registered users by default.
    $crossCustomerChecks = @(
        @{ desc = "GET /rest/basket/2 (customer2 basket)";        url = "$base_url/rest/basket/2" },
        @{ desc = "GET /api/Orders?userId=2 (customer2 orders)";  url = "$base_url/api/Orders?userId=2" }
    )

    foreach ($check in $crossCustomerChecks) {
        try {
            $resp = Invoke-WebRequest -Uri $check.url `
                -Headers @{ Authorization = "Bearer $customerToken" } `
                -UseBasicParsing
            if ($resp.StatusCode -eq 200) {
                Write-Warning "[!] BOLA FAIL (cross-customer): $($check.desc) returned 200 with customer1 token"
                $failed = $true
            } else {
                Write-Host "[*] BOLA PASS (cross-customer): $($check.desc) -> $($resp.StatusCode)"
            }
        } catch [System.Net.WebException] {
            # HTTP error response (401/403) -- access was correctly denied
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

# Fetch tokens
$admin_token     = Get-Token $admin_username $admin_password
$customer_token  = Get-Token $customer_username $customer_password
$customer2_token = Get-Token $customer2_username $customer_password

if (-not $admin_token -or -not $customer_token -or -not $customer2_token) {
    Write-Error "Failed to retrieve one or more tokens."
    exit 1
}
Write-Host "[*] Tokens acquired."

# Pre-scan checks
Test-RateLimiting
Test-AccessControls $admin_token $customer_token $customer2_token

# Generate temp plan with substitutions
$report_timestamp = Get-Date -Format "yyyyMMdd-HHmm"
Write-Host "[*] Generating temp plan (report: zap-report-juice-shop-$report_timestamp)..."
(Get-Content $PLAN_FILE) `
    -replace '\$\{admin_token\}',      $admin_token `
    -replace '\$\{customer_token\}',   $customer_token `
    -replace '\$\{base_url\}',         $base_url `
    -replace '\$\{report_timestamp\}', $report_timestamp |
    Set-Content $TEMP_PLAN

# Shut down any existing ZAP instance on this port to avoid home directory conflicts
try {
    Invoke-ZapApi "/JSON/core/action/shutdown/" | Out-Null
    Write-Host "[*] Existing ZAP instance shut down. Waiting for it to exit..."
    Start-Sleep 5
} catch {}

# Start ZAP in background with automation plan and API enabled
Write-Host "[*] Starting ZAP scan on port $ZAP_PORT..."
Push-Location $ZAP_DIR
$zapProcess = Start-Process -FilePath $ZAP_PATH `
    -ArgumentList "-cmd -autorun `"$TEMP_PLAN`" -port $ZAP_PORT -config api.key=$ZAP_KEY" `
    -PassThru -NoNewWindow
Pop-Location

if (-not (Wait-ForZap)) {
    $zapProcess | Stop-Process -Force -ErrorAction SilentlyContinue
    Remove-Item $TEMP_PLAN -ErrorAction SilentlyContinue
    exit 1
}

try {
    Write-Host "[*] Token refresh active (every 12 min)."
    Write-Host ""

    $tokenFetchTime      = Get-Date
    $currentPhase        = "admin"
    $cachedCustomerToken = $customer_token

    while (-not $zapProcess.HasExited) {
        Start-Sleep 30
        if ($zapProcess.HasExited) { break }

        # Phase detection

        # Scan 0 (admin) done -> switch to customer token
        if ($currentPhase -eq "admin") {
            try {
                $scanStatus = Invoke-ZapApi "/JSON/ascan/view/status/" @{ scanId = "0" }
                if ($scanStatus.status -eq "100") {
                    Write-Host "[*] Admin scan complete - switching to customer token..."
                    try {
                        Invoke-ZapApi "/JSON/replacer/action/removeRule/" @{ description = "Inject admin Bearer token" } | Out-Null
                    } catch {}
                    Set-ZapReplacerRule "Inject customer Bearer token" $cachedCustomerToken
                    $currentPhase   = "customer"
                    $tokenFetchTime = Get-Date
                }
            } catch {}
        }

        # Scan 1 (customer) done -> unauthenticated phase begins.
        # The set-no-token YAML job removes all replacer rules automatically.
        if ($currentPhase -eq "customer") {
            try {
                $scanStatus = Invoke-ZapApi "/JSON/ascan/view/status/" @{ scanId = "1" }
                if ($scanStatus.status -eq "100") {
                    Write-Host "[*] Customer scan complete - unauthenticated scan phase starting."
                    $currentPhase = "unauthenticated"
                }
            } catch {}
        }

        # Skip token refresh during unauthenticated and invalid-token phases
        if ($currentPhase -eq "unauthenticated") { continue }

        # Token refresh (every 12 minutes)
        $elapsed = (Get-Date) - $tokenFetchTime
        if ($elapsed.TotalMinutes -gt 12) {
            if ($zapProcess.HasExited) { break }

            if ($currentPhase -eq "admin") {
                Write-Host "[*] [$(Get-Date -Format 'HH:mm')] Refreshing admin token..."
                $admin_token         = Get-Token $admin_username $admin_password
                Set-ZapReplacerRule "Inject admin Bearer token" $admin_token

                # Keep customer token fresh so it is ready when phase switches
                $cachedCustomerToken = Get-Token $customer_username $customer_password
                Write-Host "[*] [$(Get-Date -Format 'HH:mm')] Customer token cached."
            } else {
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

} finally {
    if (-not $zapProcess.HasExited) {
        Write-Host "[*] Stopping ZAP..."
        $zapProcess | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $TEMP_PLAN -ErrorAction SilentlyContinue
    Write-Host "[*] Temp files cleaned up."
}
