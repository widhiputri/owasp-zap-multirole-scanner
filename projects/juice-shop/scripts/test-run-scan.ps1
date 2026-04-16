# Quick test for run-scan.ps1 argument parsing and YAML generation.
# Does NOT require ZAP or Juice Shop to be running.
#
# Usage: .\test-run-scan.ps1

$pass = 0
$fail = 0

function Assert-Equal($label, $actual, $expected) {
    if ($actual -eq $expected) {
        Write-Host "  PASS  $label" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  FAIL  $label" -ForegroundColor Red
        Write-Host "        expected: $expected" -ForegroundColor Yellow
        Write-Host "        actual  : $actual"   -ForegroundColor Yellow
        $script:fail++
    }
}

function Assert-Contains($label, $text, $substring) {
    if ($text -like "*$substring*") {
        Write-Host "  PASS  $label" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  FAIL  $label" -ForegroundColor Red
        Write-Host "        expected to contain: $substring" -ForegroundColor Yellow
        $script:fail++
    }
}

function Assert-NotContains($label, $text, $substring) {
    if ($text -notlike "*$substring*") {
        Write-Host "  PASS  $label" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "  FAIL  $label" -ForegroundColor Red
        Write-Host "        expected NOT to contain: $substring" -ForegroundColor Yellow
        $script:fail++
    }
}

# ---------------------------------------------------------------------------
# Inline the test-selection and Build-AutomationYaml logic
# (copy from run-scan.ps1 so we can test it in isolation)
# ---------------------------------------------------------------------------

$validTests = @(
    "all",
    "bola", "rate-limit",
    "xss", "sqli", "path-traversal", "cmd-injection", "ssrf", "xxe", "ldap",
    "admin", "customer", "unauth", "invalid-token", "auth-bypass", "passive"
)

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
    "path-traversal" = @( [pscustomobject]@{ id = 6; name = "Path Traversal" } )
    "cmd-injection"  = @(
        [pscustomobject]@{ id = 90020; name = "Remote OS Command Injection" }
        [pscustomobject]@{ id = 40032; name = "OS Command Injection (External)" }
    )
    "ssrf" = @( [pscustomobject]@{ id = 40046; name = "SSRF" } )
    "xxe"  = @( [pscustomobject]@{ id = 90023; name = "XML External Entity Attack" } )
    "ldap" = @( [pscustomobject]@{ id = 40015; name = "LDAP Injection" } )
}

$ruleCatNames = @("xss","sqli","path-traversal","cmd-injection","ssrf","xxe","ldap")
$phaseNames   = @("admin","customer","unauth","invalid-token","auth-bypass","passive")

function Resolve-TestPlan([string]$Tests) {
    $testList = ($Tests.ToLower() -split '[,\s]+') | Where-Object { $_ -ne '' } | Select-Object -Unique
    foreach ($t in $testList) {
        if ($validTests -notcontains $t) {
            throw "Unknown test '$t'"
        }
    }
    $runAll = $testList -contains "all"
    function Should-Run([string]$n) { $runAll -or ($testList -contains $n) }

    $hasRuleCat = ($testList | Where-Object { $ruleCatNames -contains $_ }).Count -gt 0
    $hasPhase   = ($testList | Where-Object { $phaseNames   -contains $_ }).Count -gt 0

    if ($runAll) {
        $runAdmin = $true; $runCustomer = $true; $runUnauth = $true; $runInvalid = $true
    } elseif ($hasRuleCat -and -not $hasPhase) {
        $runAdmin = $true; $runCustomer = $true; $runUnauth = $false; $runInvalid = $false
    } else {
        $runAdmin    = Should-Run "admin"
        $runCustomer = Should-Run "customer"
        $runUnauth   = (Should-Run "unauth")   -or (Should-Run "auth-bypass")
        $runInvalid  = (Should-Run "invalid-token") -or (Should-Run "auth-bypass")
    }

    $passiveOnly = (Should-Run "passive") -and -not ($runAdmin -or $runCustomer -or $runUnauth -or $runInvalid)

    $filteredRules = @()
    if (-not $runAll) {
        foreach ($cat in $ruleCatNames) {
            if (Should-Run $cat) { $filteredRules += $ruleCategories[$cat] }
        }
    }

    return [pscustomobject]@{
        runAdmin       = $runAdmin
        runCustomer    = $runCustomer
        runUnauth      = $runUnauth
        runInvalid     = $runInvalid
        passiveOnly    = $passiveOnly
        checkBola      = Should-Run "bola"
        checkRateLimit = Should-Run "rate-limit"
        needsZap       = $runAdmin -or $runCustomer -or $runUnauth -or $runInvalid -or $passiveOnly
        filteredRules  = $filteredRules
    }
}

function Build-AutomationYaml {
    param(
        [string]$BaseUrl, [string]$AdminToken, [string]$CustomerToken,
        [string]$ReportTimestamp,
        [bool]$RunAdmin, [bool]$RunCustomer, [bool]$RunUnauth, [bool]$RunInvalidToken,
        [bool]$PassiveOnly, [array]$FilteredRules
    )
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
    $L.Add("---"); $L.Add("env:"); $L.Add("  contexts:")
    $L.Add("    - name: juice-shop"); $L.Add("      urls:"); $L.Add("        - `"$BaseUrl`"")
    $L.Add("jobs:")
    if ($RunAdmin) {
        $L.Add("  - type: replacer"); $L.Add("    name: set-admin-token")
        $L.Add("    parameters:"); $L.Add("      deleteAllRules: true"); $L.Add("    rules:")
        $L.Add("      - description: `"Inject admin Bearer token`"")
        $L.Add("        replacementString: `"Bearer $AdminToken`"")
    } elseif ($RunCustomer) {
        $L.Add("  - type: replacer"); $L.Add("    name: set-customer-token")
        $L.Add("    parameters:"); $L.Add("      deleteAllRules: true"); $L.Add("    rules:")
        $L.Add("      - description: `"Inject customer Bearer token`"")
        $L.Add("        replacementString: `"Bearer $CustomerToken`"")
    }
    $L.Add("  - type: openapi"); $L.Add("    name: import-openapi-spec")
    $L.Add("  - type: passiveScan-wait"); $L.Add("    name: passiveScan-wait")
    if (-not $PassiveOnly) {
        if ($RunAdmin) {
            $L.Add("  - type: activeScan"); $L.Add("    name: activeScan-admin")
            foreach ($line in ($policy -split "`n")) { $L.Add($line) }
        }
        if ($RunCustomer) {
            $L.Add("  - type: activeScan"); $L.Add("    name: activeScan-customer")
            foreach ($line in ($policy -split "`n")) { $L.Add($line) }
        }
        if ($RunUnauth -or $RunInvalidToken) {
            $L.Add("  - type: replacer"); $L.Add("    name: set-no-token")
        }
        if ($RunUnauth) {
            $L.Add("  - type: activeScan"); $L.Add("    name: activeScan-unauthenticated")
            foreach ($line in ($policy -split "`n")) { $L.Add($line) }
        }
        if ($RunInvalidToken) {
            $L.Add("  - type: replacer"); $L.Add("    name: set-invalid-token")
            $L.Add("  - type: activeScan"); $L.Add("    name: activeScan-invalid-token")
            foreach ($line in ($policy -split "`n")) { $L.Add($line) }
        }
    }
    $L.Add("  - type: report"); $L.Add("    name: report-html")
    $L.Add("  - type: report"); $L.Add("    name: report-json")
    $L.Add("  - type: report"); $L.Add("    name: report-sarif")
    return ($L -join "`n")
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "=== Test selection parsing ===" -ForegroundColor Cyan

$p = Resolve-TestPlan "all"
Assert-Equal "all -> runAdmin"    $p.runAdmin    $true
Assert-Equal "all -> runCustomer" $p.runCustomer $true
Assert-Equal "all -> runUnauth"   $p.runUnauth   $true
Assert-Equal "all -> runInvalid"  $p.runInvalid  $true
Assert-Equal "all -> needsZap"    $p.needsZap    $true
Assert-Equal "all -> filtered rules count" $p.filteredRules.Count 0

$p = Resolve-TestPlan "bola"
Assert-Equal "bola -> needsZap"    $p.needsZap    $false
Assert-Equal "bola -> checkBola"   $p.checkBola   $true
Assert-Equal "bola -> runAdmin"    $p.runAdmin    $false

$p = Resolve-TestPlan "rate-limit"
Assert-Equal "rate-limit -> needsZap"       $p.needsZap       $false
Assert-Equal "rate-limit -> checkRateLimit" $p.checkRateLimit $true

$p = Resolve-TestPlan "xss,sqli"
Assert-Equal "xss,sqli -> runAdmin"    $p.runAdmin    $true
Assert-Equal "xss,sqli -> runCustomer" $p.runCustomer $true
Assert-Equal "xss,sqli -> runUnauth"   $p.runUnauth   $false
Assert-Equal "xss,sqli -> runInvalid"  $p.runInvalid  $false
Assert-Equal "xss,sqli -> rule count"  $p.filteredRules.Count (5 + 6)  # 5 xss + 6 sqli

$p = Resolve-TestPlan "xss,admin"
Assert-Equal "xss,admin -> runAdmin"    $p.runAdmin    $true
Assert-Equal "xss,admin -> runCustomer" $p.runCustomer $false
Assert-Equal "xss,admin -> rule count"  $p.filteredRules.Count 5

$p = Resolve-TestPlan "auth-bypass"
Assert-Equal "auth-bypass -> runUnauth"  $p.runUnauth  $true
Assert-Equal "auth-bypass -> runInvalid" $p.runInvalid $true
Assert-Equal "auth-bypass -> runAdmin"   $p.runAdmin   $false

$p = Resolve-TestPlan "passive"
Assert-Equal "passive -> passiveOnly" $p.passiveOnly $true
Assert-Equal "passive -> needsZap"    $p.needsZap    $true
Assert-Equal "passive -> runAdmin"    $p.runAdmin    $false

$p = Resolve-TestPlan "bola,rate-limit,xss"
Assert-Equal "combo -> checkBola"      $p.checkBola      $true
Assert-Equal "combo -> checkRateLimit" $p.checkRateLimit $true
Assert-Equal "combo -> runAdmin"       $p.runAdmin       $true
Assert-Equal "combo -> needsZap"       $p.needsZap       $true

Write-Host ""
Write-Host "=== Unknown test name validation ===" -ForegroundColor Cyan
try {
    Resolve-TestPlan "notavalidtest" | Out-Null
    Write-Host "  FAIL  invalid name should throw" -ForegroundColor Red; $fail++
} catch {
    Write-Host "  PASS  invalid name throws: $($_.Exception.Message)" -ForegroundColor Green; $pass++
}

Write-Host ""
Write-Host "=== YAML generation ===" -ForegroundColor Cyan

# Full run: all phases present, no rule filter
$p    = Resolve-TestPlan "all"
$yaml = Build-AutomationYaml -BaseUrl "http://localhost:3000" -AdminToken "tok-admin" -CustomerToken "tok-cust" `
    -ReportTimestamp "20260101-1200" -RunAdmin $p.runAdmin -RunCustomer $p.runCustomer `
    -RunUnauth $p.runUnauth -RunInvalidToken $p.runInvalid -PassiveOnly $p.passiveOnly `
    -FilteredRules $p.filteredRules
Assert-Contains "all: has activeScan-admin"         $yaml "activeScan-admin"
Assert-Contains "all: has activeScan-customer"      $yaml "activeScan-customer"
Assert-Contains "all: has activeScan-unauthenticated" $yaml "activeScan-unauthenticated"
Assert-Contains "all: has activeScan-invalid-token" $yaml "activeScan-invalid-token"
Assert-Contains "all: has set-admin-token"          $yaml "set-admin-token"
Assert-Contains "all: has admin token value"        $yaml "Bearer tok-admin"
Assert-Contains "all: defaultThreshold Medium"      $yaml "defaultThreshold: Medium"
Assert-NotContains "all: no defaultThreshold Off"   $yaml "defaultThreshold: Off"
Assert-Contains "all: has report-sarif"             $yaml "report-sarif"

# XSS only: admin+customer with filtered rules, no unauth
$p    = Resolve-TestPlan "xss"
$yaml = Build-AutomationYaml -BaseUrl "http://localhost:3000" -AdminToken "tok-admin" -CustomerToken "tok-cust" `
    -ReportTimestamp "20260101-1200" -RunAdmin $p.runAdmin -RunCustomer $p.runCustomer `
    -RunUnauth $p.runUnauth -RunInvalidToken $p.runInvalid -PassiveOnly $p.passiveOnly `
    -FilteredRules $p.filteredRules
Assert-Contains    "xss: has activeScan-admin"           $yaml "activeScan-admin"
Assert-Contains    "xss: has activeScan-customer"        $yaml "activeScan-customer"
Assert-NotContains "xss: no activeScan-unauthenticated"  $yaml "activeScan-unauthenticated"
Assert-Contains    "xss: defaultThreshold Off"           $yaml "defaultThreshold: Off"
Assert-Contains    "xss: has XSS rule 40012"             $yaml "id: 40012"
Assert-NotContains "xss: no SQLi rule 40018"             $yaml "id: 40018"

# Customer phase only (no admin)
$p    = Resolve-TestPlan "customer"
$yaml = Build-AutomationYaml -BaseUrl "http://localhost:3000" -AdminToken "" -CustomerToken "tok-cust" `
    -ReportTimestamp "20260101-1200" -RunAdmin $p.runAdmin -RunCustomer $p.runCustomer `
    -RunUnauth $p.runUnauth -RunInvalidToken $p.runInvalid -PassiveOnly $p.passiveOnly `
    -FilteredRules $p.filteredRules
Assert-NotContains "customer-only: no set-admin-token"      $yaml "set-admin-token"
Assert-Contains    "customer-only: has set-customer-token"  $yaml "set-customer-token"
Assert-Contains    "customer-only: has Bearer tok-cust"     $yaml "Bearer tok-cust"
Assert-NotContains "customer-only: no activeScan-admin"     $yaml "activeScan-admin"
Assert-Contains    "customer-only: has activeScan-customer" $yaml "activeScan-customer"

# auth-bypass: unauth + invalid-token, no admin/customer active scan
$p    = Resolve-TestPlan "auth-bypass"
$yaml = Build-AutomationYaml -BaseUrl "http://localhost:3000" -AdminToken "" -CustomerToken "" `
    -ReportTimestamp "20260101-1200" -RunAdmin $p.runAdmin -RunCustomer $p.runCustomer `
    -RunUnauth $p.runUnauth -RunInvalidToken $p.runInvalid -PassiveOnly $p.passiveOnly `
    -FilteredRules $p.filteredRules
Assert-NotContains "auth-bypass: no activeScan-admin"           $yaml "activeScan-admin"
Assert-NotContains "auth-bypass: no activeScan-customer"        $yaml "activeScan-customer"
Assert-Contains    "auth-bypass: has activeScan-unauthenticated" $yaml "activeScan-unauthenticated"
Assert-Contains    "auth-bypass: has activeScan-invalid-token"  $yaml "activeScan-invalid-token"
Assert-Contains    "auth-bypass: has set-no-token"              $yaml "set-no-token"
Assert-Contains    "auth-bypass: has set-invalid-token"         $yaml "set-invalid-token"

# passive-only: no active scans at all
$p    = Resolve-TestPlan "passive"
$yaml = Build-AutomationYaml -BaseUrl "http://localhost:3000" -AdminToken "" -CustomerToken "" `
    -ReportTimestamp "20260101-1200" -RunAdmin $p.runAdmin -RunCustomer $p.runCustomer `
    -RunUnauth $p.runUnauth -RunInvalidToken $p.runInvalid -PassiveOnly $p.passiveOnly `
    -FilteredRules $p.filteredRules
Assert-NotContains "passive: no activeScan" $yaml "activeScan"
Assert-Contains    "passive: has passiveScan-wait" $yaml "passiveScan-wait"
Assert-Contains    "passive: has report-html"      $yaml "report-html"

# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "==============================" -ForegroundColor Cyan
Write-Host "  PASSED: $pass   FAILED: $fail" -ForegroundColor $(if ($fail -eq 0) { "Green" } else { "Red" })
Write-Host "==============================" -ForegroundColor Cyan
Write-Host ""
if ($fail -gt 0) { exit 1 }
