# Invoke-MailDnsAssessment.ps1
#
# Version history
#   1  Initial release (this script plus MailDnsAssessment.psm1). MX, SPF (recursive
#      expansion, lookup and void-lookup accounting), DKIM (EOP selectors, RSA key
#      size), DMARC (incl. external report authorisation), MTA-STS and TLS-RPT, DANE,
#      DNSSEC, autodiscover and related records, apex TXT inventory,
#      internal/external vantage diff, JSON/CSV/Markdown reports, -Sanitize.

<#
.SYNOPSIS
    Read-only assessment of the DNS and mail-authentication records that matter when
    moving inbound/outbound mail filtering to Exchange Online Protection (EOP) /
    Microsoft Defender for Office 365.

.DESCRIPTION
    For every domain the script queries MX, SPF, DKIM, DMARC and related records
    (optionally MTA-STS, TLS-RPT, DANE and DNSSEC) against internal and/or external
    resolvers, evaluates them against a fixed rule set and writes JSON, CSV and
    Markdown reports. Every finding carries a stable RuleId so runs can be diffed.
    The functions live in MailDnsAssessment.psm1, which must sit next to this script.

    The script never writes to DNS, never authenticates to a tenant and never sends
    mail. It uses built-in modules only (DnsClient Resolve-DnsName, Invoke-WebRequest)
    plus .NET sockets for the DNSSEC-aware queries Resolve-DnsName cannot express.

.PARAMETER DomainList
    Text file with one domain per line. '#' starts a comment. Defaults to domains.txt
    next to the script when neither -DomainList nor -Domain is given.

.PARAMETER Domain
    One or more domains for ad-hoc runs. Can be combined with -DomainList.

.PARAMETER Vantage
    Internal, External or Both (default). Both runs every query against both resolver
    sets and adds a cross-vantage diff.

.PARAMETER InternalResolver
    Internal resolvers. Defaults to the DNS servers configured on this machine.

.PARAMETER ExternalResolver
    External resolvers. Default 1.1.1.1, 8.8.8.8, 9.9.9.9.

.PARAMETER DkimSelector
    Additional DKIM selectors to probe. selector1 and selector2 are always probed.

.PARAMETER CheckMtaSts
    Query _mta-sts and _smtp._tls TXT records and fetch the MTA-STS policy over HTTPS.

.PARAMETER CheckDane
    Query TLSA records (_25._tcp.<mx>) with DNSSEC OK and report validation.

.PARAMETER CheckDnssec
    Query SOA and MX with DNSSEC OK and report the AD flag per vantage.

.PARAMETER OutputPath
    Folder for the reports. Default: .\output next to the script.

.PARAMETER Sanitize
    Replace domain names and host names with stable pseudonyms and mask IP addresses
    in all report files so they can be shared outside the organisation.

.PARAMETER TimeoutSeconds
    Timeout per DNS query and resolver (default 5).

.EXAMPLE
    .\Invoke-MailDnsAssessment.ps1 -Domain example.com -Vantage External

.EXAMPLE
    .\Invoke-MailDnsAssessment.ps1 -DomainList .\domains.txt -CheckMtaSts -CheckDane -CheckDnssec -Sanitize

.EXAMPLE
    .\Invoke-MailDnsAssessment.ps1 -Domain example.com,example.net -InternalResolver 192.0.2.53 -DkimSelector s1,k1 -Verbose
#>
[CmdletBinding()]
param(
    [string]$DomainList,
    [string[]]$Domain,
    [ValidateSet('Internal', 'External', 'Both')]
    [string]$Vantage = 'Both',
    [string[]]$InternalResolver,
    [string[]]$ExternalResolver = @('1.1.1.1', '8.8.8.8', '9.9.9.9'),
    [string[]]$DkimSelector,
    [switch]$CheckMtaSts,
    [switch]$CheckDane,
    [switch]$CheckDnssec,
    [string]$OutputPath,
    [switch]$Sanitize,
    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 5
)

$ScriptVersion = 1

# Functions live in MailDnsAssessment.psm1 next to this script; both files carry the same version.
$modulePath = Join-Path $PSScriptRoot 'MailDnsAssessment.psm1'
if (-not (Test-Path -LiteralPath $modulePath)) { throw 'MailDnsAssessment.psm1 must be in the same folder as the script.' }
Import-Module -Name $modulePath -Force -DisableNameChecking -ErrorAction Stop
$moduleVersion = Get-MailDnsAssessmentVersion
if ($moduleVersion -ne $ScriptVersion) { throw "Version mismatch: script $ScriptVersion, module $moduleVersion. Copy both files from the same release." }

if (-not $DomainList -and -not $Domain) {
    $defaultList = Join-Path $PSScriptRoot 'domains.txt'
    if (Test-Path -LiteralPath $defaultList) { $DomainList = $defaultList }
    else { throw 'Specify -Domain or -DomainList (or create domains.txt next to the script).' }
}
$names = @(Get-DomainInput -DomainList $DomainList -Domain $Domain)
if ($names.Count -eq 0) { throw 'No valid domain to assess.' }
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot 'output' }

$run = Invoke-Assessment -DomainName $names -Vantage $Vantage -InternalResolver $InternalResolver -ExternalResolver $ExternalResolver `
    -DkimSelector $DkimSelector -CheckMtaSts:$CheckMtaSts -CheckDane:$CheckDane -CheckDnssec:$CheckDnssec `
    -OutputPath $OutputPath -Sanitize:$Sanitize -TimeoutSeconds $TimeoutSeconds -ScriptVersion $ScriptVersion `
    -Verbose:($VerbosePreference -eq 'Continue')

Write-Host "JSON:     $($run.Paths.Json)"
Write-Host "CSV:      $($run.Paths.Csv)"
Write-Host "Markdown: $($run.Paths.Markdown)"
$run.Results | ForEach-Object { $_.Summary } |
    Select-Object Domain, MxClass, SpfLookups, SpfAll, DkimSelector1, DkimSelector2, DmarcP, Critical, High, Medium, Info

# Version: 1
