# ZAP Clean Report Generator
#
# Converts a ZAP JSON report into a clean, readable HTML report suitable
# for sharing with anyone -- not just security engineers.
#
# Usage:
#   .\generate-report.ps1 -JsonReport ..\..\reports\zap-report-juice-shop-20260415-2335.json
#   .\generate-report.ps1 -JsonReport <path>.json -OutFile <path>.html

param (
    [Parameter(Mandatory=$true)]
    [string]$JsonReport,
    [string]$OutFile
)

if (-not (Test-Path $JsonReport)) {
    Write-Error "Report file not found: $JsonReport"
    exit 1
}

if (-not $OutFile) {
    $OutFile = [System.IO.Path]::Combine(
        [System.IO.Path]::GetDirectoryName($JsonReport),
        [System.IO.Path]::GetFileNameWithoutExtension($JsonReport) + ".clean.html"
    )
}

# ---- Parse JSON ---------------------------------------------------------------

$report  = Get-Content $JsonReport -Raw | ConvertFrom-Json
$site    = $report.site[0]
$target  = $site.'@name'
$zapVer  = $report.'@version'
$genDate = $report.'@generated'

# Collect and sort alerts (highest risk first), drop false positives
$alerts = $site.alerts |
    Where-Object { $_.riskdesc -notmatch 'False Positive' -and [int]$_.riskcode -ge 0 } |
    Sort-Object { [int]$_.riskcode } -Descending

# ---- Reference data -----------------------------------------------------------

$cweNames = @{
    '16'   = 'Configuration'
    '22'   = 'Path Traversal'
    '78'   = 'OS Command Injection'
    '79'   = 'Cross-Site Scripting (XSS)'
    '89'   = 'SQL Injection'
    '90'   = 'LDAP Injection'
    '93'   = 'Header Injection'
    '94'   = 'Code Injection'
    '113'  = 'HTTP Response Splitting'
    '200'  = 'Information Exposure'
    '209'  = 'Error Message Information Exposure'
    '264'  = 'Permissions, Privileges and Access Controls'
    '284'  = 'Improper Access Control'
    '285'  = 'Improper Authorization'
    '287'  = 'Improper Authentication'
    '295'  = 'Improper Certificate Validation'
    '310'  = 'Cryptographic Issues'
    '311'  = 'Missing Encryption of Sensitive Data'
    '319'  = 'Cleartext Transmission of Sensitive Information'
    '326'  = 'Inadequate Encryption Strength'
    '352'  = 'Cross-Site Request Forgery (CSRF)'
    '359'  = 'Privacy Violation'
    '400'  = 'Uncontrolled Resource Consumption'
    '434'  = 'Unrestricted File Upload'
    '502'  = 'Deserialization of Untrusted Data'
    '521'  = 'Weak Password Requirements'
    '522'  = 'Insufficiently Protected Credentials'
    '525'  = 'Information Exposure Through Browser Caching'
    '601'  = 'Open Redirect'
    '611'  = 'XML External Entity (XXE)'
    '613'  = 'Insufficient Session Expiration'
    '614'  = 'Sensitive Cookie Without Secure Attribute'
    '693'  = 'Protection Mechanism Failure'
    '732'  = 'Incorrect Permission Assignment'
    '778'  = 'Insufficient Logging'
    '829'  = 'Inclusion of Functionality from Untrusted Control Sphere'
    '918'  = 'Server-Side Request Forgery (SSRF)'
    '1021' = 'Improper Restriction of Rendered UI Layers (Clickjacking)'
    '1275' = 'Sensitive Cookie with Improper SameSite Attribute'
}

$wascNames = @{
    '1'  = 'Insufficient Authentication'
    '2'  = 'Insufficient Authorization'
    '4'  = 'Insufficient Transport Layer Protection'
    '7'  = 'Cross-Site Scripting (XSS)'
    '8'  = 'Cross-Site Request Forgery (CSRF)'
    '9'  = 'Information Leakage'
    '13' = 'Content Spoofing'
    '14' = 'Credential / Session Prediction'
    '15' = 'Application Misconfiguration'
    '17' = 'Path Traversal'
    '19' = 'SQL Injection'
    '20' = 'Improper Input Handling'
    '21' = 'Insufficient Anti-Automation'
    '22' = 'Improper Error Handling'
    '34' = 'Predictable Resource Location'
    '38' = 'URL Redirector Abuse'
    '42' = 'Abuse of Functionality'
    '45' = 'Fingerprinting'
    '49' = 'Insufficient Session Expiration'
}

# ---- Helpers ------------------------------------------------------------------

function Get-RiskLabel($code) {
    switch ([int]$code) {
        3 { 'High' } 2 { 'Medium' } 1 { 'Low' } 0 { 'Info' } default { 'Unknown' }
    }
}

function Get-ConfidenceLabel($code) {
    switch ([int]$code) {
        4 { 'Confirmed' } 3 { 'High' } 2 { 'Medium' } 1 { 'Low' } default { 'Unknown' }
    }
}

function Get-ConfidenceTooltip($code) {
    switch ([int]$code) {
        4 { 'Confirmed: ZAP verified this with certainty. The vulnerability was proven in the response.' }
        3 { 'High confidence: ZAP is very likely correct. Manual verification is still recommended.' }
        2 { 'Medium confidence: ZAP is fairly certain, but some false positives are possible. Investigate before acting.' }
        1 { 'Low confidence: ZAP detected a possible issue but it may be a false positive. Treat as a lead, not a fact.' }
        default { 'Unknown confidence level.' }
    }
}

function EscHtml($text) {
    if (-not $text) { return '' }
    $text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

function Get-CweBadge($id) {
    if (-not $id -or $id -eq '0') { return '' }
    $name    = if ($cweNames.ContainsKey($id)) { $cweNames[$id] } else { 'See MITRE for details' }
    $tooltip = "CWE-${id}: $name"
    return "<a class='badge meta-badge' href='https://cwe.mitre.org/data/definitions/${id}.html' target='_blank' rel='noopener' title='$tooltip'>CWE-${id}</a>"
}

function Get-WascBadge($id) {
    if (-not $id -or $id -eq '0') { return '' }
    $name    = if ($wascNames.ContainsKey($id)) { $wascNames[$id] } else { 'Web Application Security Consortium category' }
    $tooltip = "WASC-${id}: $name"
    return "<span class='badge meta-badge' title='$tooltip'>WASC-${id}</span>"
}

# ---- Summary counts -----------------------------------------------------------

$counts = @{ High = 0; Medium = 0; Low = 0; Info = 0 }
foreach ($a in $alerts) {
    $counts[(Get-RiskLabel $a.riskcode)]++
}

# ---- Legend HTML --------------------------------------------------------------

$legendHtml = @'
<details class="legend">
  <summary class="legend-summary">How to read this report</summary>
  <div class="legend-body">

    <div class="legend-group">
      <div class="legend-group-title">Risk Level</div>
      <div class="legend-grid">
        <div class="legend-key"><span class="legend-dot" style="background:#c62828"></span><strong>High</strong></div>
        <div class="legend-val">Serious vulnerability. Could directly lead to data loss, account takeover, or system compromise. Fix immediately.</div>
        <div class="legend-key"><span class="legend-dot" style="background:#e64a19"></span><strong>Medium</strong></div>
        <div class="legend-val">Significant issue that increases attack surface. Should be fixed in the near term.</div>
        <div class="legend-key"><span class="legend-dot" style="background:#9e9d24"></span><strong>Low</strong></div>
        <div class="legend-val">Minor weakness or defence-in-depth gap. Low immediate risk but worth addressing.</div>
        <div class="legend-key"><span class="legend-dot" style="background:#1565c0"></span><strong>Info</strong></div>
        <div class="legend-val">Informational finding. No direct risk but may assist an attacker in reconnaissance.</div>
      </div>
    </div>

    <div class="legend-group">
      <div class="legend-group-title">Confidence</div>
      <div class="legend-grid">
        <div class="legend-key"><strong>Confirmed</strong></div>
        <div class="legend-val">Verified with certainty in the server response.</div>
        <div class="legend-key"><strong>High</strong></div>
        <div class="legend-val">Very likely a real issue. Manual verification still recommended.</div>
        <div class="legend-key"><strong>Medium</strong></div>
        <div class="legend-val">Probably real, but some false positives are possible.</div>
        <div class="legend-key"><strong>Low</strong></div>
        <div class="legend-val">Possible issue. Treat as a lead, not a confirmed finding.</div>
      </div>
    </div>

    <div class="legend-group">
      <div class="legend-group-title">Badges</div>
      <div class="legend-grid">
        <div class="legend-key"><strong>CWE-&lt;n&gt;</strong></div>
        <div class="legend-val">Common Weakness Enumeration. A standardised ID for a type of software weakness. Click the badge to open the MITRE description.</div>
        <div class="legend-key"><strong>WASC-&lt;n&gt;</strong></div>
        <div class="legend-val">Web Application Security Consortium classification. Hover the badge to see the category name.</div>
      </div>
    </div>

  </div>
</details>
'@

# ---- Build findings HTML ------------------------------------------------------

$riskMeta = @{
    High   = @{ color = '#b71c1c'; bg = '#ffebee'; border = '#ef9a9a'; pill = '#c62828' }
    Medium = @{ color = '#bf360c'; bg = '#fff3e0'; border = '#ffcc80'; pill = '#e64a19' }
    Low    = @{ color = '#827717'; bg = '#f9fbe7'; border = '#dce775'; pill = '#9e9d24' }
    Info   = @{ color = '#0d47a1'; bg = '#e3f2fd'; border = '#90caf9'; pill = '#1565c0' }
}

$findingsHtml = ''

foreach ($level in @('High','Medium','Low','Info')) {
    $group = $alerts | Where-Object { (Get-RiskLabel $_.riskcode) -eq $level }
    if (-not $group) { continue }

    $m = $riskMeta[$level]
    $groupCount = @($group).Count

    $findingsHtml += "<section class='risk-section'>"
    $findingsHtml += "<h2 class='risk-heading' style='color:$($m.color);border-color:$($m.color)'>"
    $findingsHtml += "$level Risk <span class='risk-pill' style='background:$($m.pill)'>$groupCount</span></h2>"

    foreach ($alert in @($group)) {
        $riskLabel  = Get-RiskLabel $alert.riskcode
        $confLabel  = Get-ConfidenceLabel $alert.confidence
        $confTip    = Get-ConfidenceTooltip $alert.confidence
        $instCount  = @($alert.instances).Count
        $totalCount = if ($alert.count -and [int]$alert.count -gt $instCount) { [int]$alert.count } else { $instCount }
        $showMore   = if ($totalCount -gt $instCount) { " <span class='show-more'>(showing $instCount of $totalCount)</span>" } else { '' }

        # Badges
        $badges  = "<span class='badge risk-badge' style='background:$($m.pill)'>$riskLabel</span>"
        $badges += "<span class='badge conf-badge' title='$confTip'>Confidence: $confLabel</span>"
        $badges += Get-CweBadge  $alert.cweid
        $badges += Get-WascBadge $alert.wascid

        # URL list
        $urlRows = ''
        foreach ($inst in @($alert.instances)) {
            $uri    = EscHtml $inst.uri
            $method = EscHtml $inst.method
            $param  = if ($inst.param)    { "<span class='param-tag'>$(EscHtml $inst.param)</span>" }    else { '' }
            $evid   = if ($inst.evidence) { "<div class='evidence'>Evidence: <code>$(EscHtml $inst.evidence)</code></div>" } else { '' }
            $other  = if ($inst.otherinfo -and $inst.otherinfo.Trim()) {
                          "<div class='otherinfo'>$(EscHtml $inst.otherinfo)</div>"
                      } else { '' }
            $urlRows += "<li><span class='http-method'>$method</span><span class='uri'>$uri</span>$param$evid$other</li>"
        }

        $findingsHtml += @"
<details class='finding' style='border-left-color:$($m.border);background:$($m.bg)'>
  <summary class='finding-summary'>
    <span class='chevron'>&#9658;</span>
    <span class='finding-title'>$(EscHtml $alert.name)</span>
    <span class='finding-badges'>$badges<span class='url-count'>$instCount URL$(if($instCount -ne 1){'s'})$showMore</span></span>
  </summary>
  <div class='finding-body'>
    <div class='finding-col'>
      <div class='section-block'>
        <div class='section-label'>What is this?</div>
        <div class='section-content'>$($alert.desc)</div>
      </div>
      <div class='section-block'>
        <div class='section-label'>How to fix it</div>
        <div class='section-content'>$($alert.solution)</div>
      </div>
    </div>
    <div class='finding-col'>
      <div class='section-block'>
        <div class='section-label'>Affected URLs ($instCount)$showMore</div>
        <ul class='url-list'>$urlRows</ul>
      </div>
    </div>
  </div>
</details>
"@
    }

    $findingsHtml += '</section>'
}

if (-not $findingsHtml) {
    $findingsHtml = "<div class='no-findings'>No findings detected.</div>"
}

# ---- Assemble full HTML -------------------------------------------------------

$css = @'
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;font-size:14px;line-height:1.6;color:#212121;background:#f0f2f5}
a{color:inherit;text-decoration:none}
a:hover{text-decoration:underline}

header{background:linear-gradient(135deg,#1a237e,#283593);color:#fff;padding:28px 40px}
header h1{font-size:20px;font-weight:700;letter-spacing:.3px}
header .meta{font-size:12px;opacity:.75;margin-top:6px}
header .meta span{margin-right:16px}

.container{max-width:1080px;margin:0 auto;padding:28px 20px}

.summary{display:flex;gap:14px;margin-bottom:20px;flex-wrap:wrap}
.summary-card{flex:1;min-width:110px;background:#fff;border-radius:10px;padding:20px 16px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.1)}
.summary-card .num{font-size:40px;font-weight:800;line-height:1}
.summary-card .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.8px;font-weight:600;margin-top:4px}
.card-h .num,.card-h .lbl{color:#c62828}
.card-m .num,.card-m .lbl{color:#e64a19}
.card-l .num,.card-l .lbl{color:#9e9d24}
.card-i .num,.card-i .lbl{color:#1565c0}
.card-total .num,.card-total .lbl{color:#37474f}

.legend{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:28px;overflow:hidden}
.legend-summary{padding:8px 14px;cursor:pointer;font-size:15px;font-weight:700;color:#455a64;list-style:none;user-select:none;display:flex;align-items:center;gap:8px}
.legend-summary::-webkit-details-marker{display:none}
.legend-summary::before{content:'\25B6';font-size:10px;color:#90a4ae;transition:transform .15s;display:inline-block}
details.legend[open] .legend-summary::before{transform:rotate(90deg)}
.legend-body{padding:16px 18px;border-top:1px solid #eceff1;display:flex;gap:24px;flex-wrap:wrap}
.legend-group{flex:1;min-width:220px}
.legend-group-title{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#90a4ae;font-weight:700;margin-bottom:8px}
.legend-grid{display:grid;grid-template-columns:max-content 1fr;gap:6px 14px;align-items:baseline}
.legend-key{display:flex;align-items:center;gap:6px;font-size:12px;white-space:nowrap}
.legend-val{font-size:12px;color:#546e7a}
.legend-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}

.risk-section{margin-bottom:28px}
.risk-heading{font-size:15px;font-weight:700;padding:8px 14px;border-left:4px solid;margin-bottom:10px;display:flex;align-items:center;gap:8px;background:#fff;border-radius:0 6px 6px 0;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.risk-pill{color:#fff;font-size:11px;padding:2px 9px;border-radius:10px;font-weight:600}

.finding{border-left:4px solid;border-radius:0 8px 8px 0;margin-bottom:8px;box-shadow:0 1px 3px rgba(0,0,0,.08);overflow:hidden}
.finding-summary{padding:13px 16px;cursor:pointer;display:flex;align-items:center;gap:10px;list-style:none;user-select:none}
.finding-summary::-webkit-details-marker{display:none}
.chevron{font-size:10px;color:#999;flex-shrink:0;transition:transform .15s;display:inline-block}
details.finding[open] .chevron{transform:rotate(90deg)}
.finding-title{font-weight:600;font-size:14px;flex:1}
.finding-badges{display:flex;align-items:center;gap:5px;flex-wrap:wrap;justify-content:flex-end}

.badge{font-size:11px;padding:2px 7px;border-radius:4px;font-weight:600;white-space:nowrap;cursor:default}
.risk-badge{color:#fff}
.conf-badge{background:#eeeeee;color:#555}
.meta-badge{background:#e8eaf6;color:#3949ab}
a.meta-badge:hover{background:#c5cae9;text-decoration:none}
.url-count{font-size:12px;color:#777;white-space:nowrap}
.show-more{font-size:11px;color:#9e9e9e;font-style:italic}

.finding-body{padding:16px;border-top:1px solid rgba(0,0,0,.07);display:flex;gap:20px;flex-wrap:wrap}
.finding-col{flex:1;min-width:260px}
.section-block{margin-bottom:16px}
.section-label{font-size:11px;text-transform:uppercase;letter-spacing:.6px;color:#757575;font-weight:600;margin-bottom:6px}
.section-content{font-size:13px;color:#37474f}
.section-content p{margin-bottom:6px}
.section-content ul{padding-left:18px}
.section-content li{margin-bottom:3px}

.url-list{list-style:none;display:flex;flex-direction:column;gap:5px}
.url-list li{background:#fff;border:1px solid #e0e0e0;border-radius:5px;padding:7px 10px;font-size:12px;word-break:break-all}
.http-method{display:inline-block;font-weight:700;font-size:10px;padding:2px 6px;background:#e8eaf6;color:#283593;border-radius:3px;margin-right:6px;vertical-align:middle;flex-shrink:0}
.uri{color:#37474f;vertical-align:middle}
.param-tag{display:inline-block;font-size:10px;background:#fce4ec;color:#b71c1c;padding:1px 6px;border-radius:3px;margin-left:6px;vertical-align:middle}
.evidence{margin-top:5px;font-size:11px;color:#555}
.evidence code,.otherinfo code{background:#f5f5f5;padding:1px 4px;border-radius:2px;font-family:'Consolas','Monaco',monospace;font-size:11px;word-break:break-all}
.otherinfo{margin-top:4px;font-size:11px;color:#666}

.no-findings{text-align:center;padding:60px;color:#388e3c;font-size:18px;font-weight:600;background:#fff;border-radius:10px;box-shadow:0 1px 4px rgba(0,0,0,.1)}

footer{text-align:center;padding:20px;color:#9e9e9e;font-size:12px}
'@

$totalCount = $counts.High + $counts.Medium + $counts.Low + $counts.Info

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Scan Report</title>
<style>$css</style>
</head>
<body>

<header>
  <h1>Security Scan Report</h1>
  <div class="meta">
    <span>Target: <strong>$target</strong></span>
    <span>Generated: $genDate</span>
    <span>ZAP $zapVer</span>
  </div>
</header>

<div class="container">

  <div class="summary">
    <div class="summary-card card-total">
      <div class="num">$totalCount</div>
      <div class="lbl">Total</div>
    </div>
    <div class="summary-card card-h">
      <div class="num">$($counts.High)</div>
      <div class="lbl">High</div>
    </div>
    <div class="summary-card card-m">
      <div class="num">$($counts.Medium)</div>
      <div class="lbl">Medium</div>
    </div>
    <div class="summary-card card-l">
      <div class="num">$($counts.Low)</div>
      <div class="lbl">Low</div>
    </div>
    <div class="summary-card card-i">
      <div class="num">$($counts.Info)</div>
      <div class="lbl">Info</div>
    </div>
  </div>

  $legendHtml

  $findingsHtml

</div>

<footer>OWASP ZAP $zapVer &bull; $genDate</footer>
</body>
</html>
"@

[System.IO.File]::WriteAllText($OutFile, $html, [System.Text.UTF8Encoding]::new($false))
Write-Host "[*] Clean report: $OutFile"
