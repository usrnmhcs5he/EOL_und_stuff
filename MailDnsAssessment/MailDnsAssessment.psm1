# MailDnsAssessment.psm1
#
# Functions of Invoke-MailDnsAssessment.ps1, grouped by check. The version history is
# kept in the header of Invoke-MailDnsAssessment.ps1; script and module always carry
# the same version number and the script refuses to run with a mismatched module.
#

$script:ModuleVersion = 1
$script:RuleCatalog = $null
$script:DnsClientRunspace = $null

#region Rule catalog and findings

function Get-RuleCatalog {
    # RuleId|Severity|Check|Title|Recommendation. Severity and check are fixed per rule.
    $rows = @(
        'DOMAIN-001|Critical|Domain|Domain does not exist (NXDOMAIN)|Correct the domain name or remove it from scope.'
        'DNS-001|Medium|DNS|Query failed on every resolver of the vantage|Check resolver reachability; results for this record are incomplete.'
        'MX-001|Critical|MX|No MX record|Publish MX records, or a null MX (0 .) if the domain does not receive mail.'
        'MX-002|High|MX|Microsoft and non-Microsoft MX targets mixed (bypass path)|Remove the non-Microsoft MX hosts after cutover so mail cannot bypass EOP.'
        'MX-003|High|MX|MX target is a CNAME|Point the MX at a host name that has A/AAAA records (RFC 2181 section 10.3).'
        'MX-004|Medium|MX|MX TTL above 3600 seconds (slow cutover)|Lower the MX TTL (300-3600) at least one old TTL before the cutover.'
        'MX-005|Info|MX|MX TTL below 300 seconds|Raise the TTL once the cutover is stable.'
        'MX-006|Critical|MX|MX host does not resolve to an address|Fix the A/AAAA records of the MX host or remove it from the MX set.'
        'MX-007|Info|MX|MX does not point to EOP|Expected before cutover; after cutover the MX points to EOP.'
        'MX-008|Info|MX|Null MX published (domain does not accept mail)|None if the domain is not meant to receive mail.'
        'MX-009|Info|MX|EOP MX without DANE (mail.protection.outlook.com)|Consider the DANE-enabled mx.microsoft host when enabling inbound SMTP DANE.'
        'MX-010|Info|MX|Legacy and DANE-enabled EOP MX hosts both published|Remove the legacy host once the DANE migration is complete.'
        'SPF-001|High|SPF|No SPF record|Publish one v=spf1 record (v=spf1 -all for domains that send no mail).'
        'SPF-002|Critical|SPF|Multiple SPF records (permerror)|Merge into a single v=spf1 record.'
        'SPF-003|Critical|SPF|SPF DNS lookups exceed 10 (permerror)|Remove or flatten includes; replace a/mx with ip4/ip6.'
        'SPF-004|Medium|SPF|SPF DNS lookups at 8 or more (little headroom)|Reduce lookups before adding senders.'
        'SPF-005|Critical|SPF|SPF void lookups exceed 2 (permerror)|Remove mechanisms that point to names without records.'
        'SPF-006|Critical|SPF|SPF +all authorises every host|Replace +all with -all or ~all.'
        'SPF-007|Medium|SPF|SPF has no all mechanism and no redirect|End the record with -all or ~all.'
        'SPF-008|Medium|SPF|SPF ptr mechanism used (deprecated)|Replace ptr with ip4/ip6 ranges.'
        'SPF-009|Info|SPF|SPF a or mx mechanism costs a lookup|Replace with ip4/ip6 where the addresses are stable.'
        'SPF-010|Critical|SPF|SPF include or redirect target has no SPF record (permerror)|Fix or remove the include or redirect.'
        'SPF-011|Info|SPF|spf.protection.outlook.com is authorised|None.'
        'SPF-012|High|SPF|spf.protection.outlook.com is not authorised|Add include:spf.protection.outlook.com before EOP sends mail for the domain.'
        'SPF-013|High|SPF|Adding spf.protection.outlook.com would exceed 10 lookups|Free lookups before the cutover.'
        'SPF-014|Info|SPF|SPF macros present (not expanded)|Review macro mechanisms manually.'
        'SPF-015|Critical|SPF|SPF syntax error (permerror)|Correct the record syntax.'
        'SPF-016|Medium|SPF|SPF ends with ?all (neutral)|Use ~all or -all.'
        'SPF-017|Critical|SPF|SPF include loop|Remove the circular include.'
        'SPF-018|Info|SPF|SPF ends with ~all (softfail)|Acceptable with DMARC enforcement; -all is stricter.'
        'DKIM-001|High|DKIM|Neither EOP DKIM selector published|Publish the selector1 and selector2 CNAMEs shown in the Defender portal before enabling DKIM signing in EOP.'
        'DKIM-002|Medium|DKIM|Only one EOP DKIM selector published|Publish both selector1 and selector2; EOP key rotation alternates between them.'
        'DKIM-003|Medium|DKIM|Requested DKIM selector not found|Check the selector name or publish the key.'
        'DKIM-004|High|DKIM|EOP selector published as TXT instead of CNAME|Replace with the CNAME to the tenant; a static TXT breaks EOP key rotation.'
        'DKIM-005|Medium|DKIM|DKIM RSA key shorter than 2048 bits|Rotate to a 2048-bit key.'
        'DKIM-006|High|DKIM|DKIM RSA key shorter than 1024 bits|Rotate to a 2048-bit key; receivers ignore short keys.'
        'DKIM-007|Info|DKIM|DKIM key revoked (empty p=)|Remove the record when it is no longer needed.'
        'DKIM-008|High|DKIM|DKIM key record invalid or key not decodable|Republish the key record.'
        'DKIM-009|Medium|DKIM|EOP selector CNAME points to a non-Microsoft target|Repoint to the target shown in the Defender portal before enabling EOP DKIM.'
        'DKIM-010|Info|DKIM|Non-RSA DKIM key|Keep an RSA key published as well; not all receivers verify Ed25519.'
        'DKIM-011|Medium|DKIM|DKIM CNAME target has no key record|Expected until DKIM is enabled in the tenant; otherwise fix the dangling CNAME.'
        'DKIM-012|Info|DKIM|DKIM key in test mode (t=y)|Remove t=y once signing is verified.'
        'DKIM-013|Medium|DKIM|DKIM key restricted to SHA-1 (h=sha1)|Remove h=sha1 (RFC 8301).'
        'DKIM-014|Medium|DKIM|Multiple DKIM key records at one selector|Publish one key record per selector.'
        'DKIM-015|Medium|DKIM|EOP selector CNAME refers to the other selector|Point selector1 at selector1-... and selector2 at selector2-... .'
        'DMARC-001|High|DMARC|No DMARC record|Publish _dmarc TXT v=DMARC1 with rua and progress to enforcement.'
        'DMARC-002|Critical|DMARC|Multiple DMARC records (policy ignored)|Keep exactly one record.'
        'DMARC-003|Medium|DMARC|DMARC policy p=none (monitoring only)|Move to quarantine or reject once the reports are clean.'
        'DMARC-004|Medium|DMARC|DMARC pct below 100|Raise pct to 100.'
        'DMARC-005|Medium|DMARC|DMARC sp not set while subdomains are in scope|Set sp explicitly.'
        'DMARC-006|Medium|DMARC|DMARC rua not set (no aggregate reports)|Add rua=mailto:... .'
        'DMARC-007|Medium|DMARC|DMARC report destination lacks external authorisation|The destination domain must publish <domain>._report._dmarc.<destination> TXT v=DMARC1.'
        'DMARC-008|Info|DMARC|DMARC ruf present (failure reports)|Check the privacy implications; few receivers send ruf reports.'
        'DMARC-009|High|DMARC|DMARC record syntax error|Correct the record.'
        'DMARC-010|Info|DMARC|DMARC strict alignment (adkim=s or aspf=s)|Make sure every sender signs and sends with the exact domain.'
        'DMARC-011|Medium|DMARC|DMARC sp=none weaker than p|Align sp with p.'
        'DMARC-012|Info|DMARC|No DMARC record; parent domain policy applies|Publish an explicit record if this domain needs a different policy.'
        'DMARC-013|Medium|DMARC|DMARC record published at the apex|Move the record to _dmarc.<domain>; receivers ignore it at the apex.'
        'MTASTS-001|Info|MTA-STS|MTA-STS not published|Consider MTA-STS in testing mode after the cutover.'
        'MTASTS-002|High|MTA-STS|MTA-STS TXT published but policy not retrievable|Publish the policy at https://mta-sts.<domain>/.well-known/mta-sts.txt or remove the TXT.'
        'MTASTS-003|Medium|MTA-STS|MTA-STS policy published without _mta-sts TXT|Publish _mta-sts TXT v=STSv1; id=... .'
        'MTASTS-004|Critical|MTA-STS|MTA-STS enforce policy does not cover all MX hosts|Add the MX hosts to the policy and change the id before changing MX.'
        'MTASTS-005|Medium|MTA-STS|MTA-STS testing policy does not cover all MX hosts|Add the MX hosts to the policy.'
        'MTASTS-006|Info|MTA-STS|MTA-STS mode none or testing|Move to enforce once TLS-RPT reports are clean.'
        'MTASTS-007|Medium|MTA-STS|MTA-STS max_age below 86400|Use a max_age of at least one day (RFC 8461 recommends weeks).'
        'MTASTS-008|High|MTA-STS|MTA-STS policy host certificate invalid|Serve the policy with a valid certificate for mta-sts.<domain>.'
        'MTASTS-009|High|MTA-STS|MTA-STS policy syntax invalid|Correct version, mode, mx and max_age lines.'
        'MTASTS-010|Medium|MTA-STS|MTA-STS TXT record invalid|Publish v=STSv1; id=<new id>.'
        'MTASTS-011|High|MTA-STS|MTA-STS enforce policy does not allow EOP MX (cutover blocker)|Add *.mail.protection.outlook.com (or the mx.microsoft host) to the policy, change the id and wait max_age before changing MX.'
        'MTASTS-012|Medium|MTA-STS|MTA-STS certificate expires within 30 days|Renew the certificate.'
        'MTASTS-013|Medium|MTA-STS|MTA-STS policy not served as text/plain|Serve the policy with Content-Type text/plain.'
        'TLSRPT-001|Info|MTA-STS|No TLS-RPT record|Publish _smtp._tls TXT v=TLSRPTv1; rua=mailto:... .'
        'TLSRPT-002|Medium|MTA-STS|TLS-RPT record invalid|Publish v=TLSRPTv1 with at least one rua.'
        'DANE-001|Medium|DANE|TLSA published in an unsigned zone (DANE ineffective)|Sign the zone with DNSSEC or remove the TLSA records.'
        'DANE-002|Info|DANE|TLSA present but the resolver did not validate|Re-run against a validating resolver to confirm.'
        'DANE-003|Info|DANE|No TLSA record for MX host|None unless inbound DANE is intended.'
        'DANE-004|Medium|DANE|TLSA uses PKIX usage 0 or 1 (unsuitable for SMTP)|Use usage 2 (DANE-TA) or 3 (DANE-EE) per RFC 7672.'
        'DANE-005|High|DANE|TLSA lookup failed (SERVFAIL)|Fix DNSSEC for the MX host zone; DANE senders defer mail while the lookup fails.'
        'DNSSEC-001|Info|DNSSEC|Zone not signed|None unless DNSSEC or DANE is intended.'
        'DNSSEC-002|Info|DNSSEC|Zone signed but the resolver did not validate (AD not set)|Use a validating resolver to confirm the chain of trust.'
        'DNSSEC-003|Critical|DNSSEC|DNSSEC validation fails (bogus)|Fix the DS/DNSKEY chain; validating resolvers cannot resolve the domain.'
        'DNSSEC-004|Medium|DNSSEC|DNSSEC validation differs between internal and external|Check internal resolver validation settings and forwarders.'
        'AUTOD-001|Info|Autodiscover|Autodiscover not published|Publish autodiscover CNAME autodiscover.outlook.com for Exchange Online mailboxes.'
        'AUTOD-002|Info|Autodiscover|Autodiscover does not point to Exchange Online|Expected for hybrid; point to autodiscover.outlook.com after mailbox migration.'
        'OTHER-001|Info|Other|Legacy msoid CNAME present|Remove the msoid record unless it is required (21Vianet).'
        'OTHER-002|Info|Other|Teams/Skype or device registration records present|Informational.'
        'TXT-001|Info|TXT|Verification tokens present at the apex|Remove tokens of services no longer in use.'
        'TXT-002|Info|TXT|Multiple Microsoft 365 verification tokens (MS=)|Remove stale MS= tokens.'
        'VANTAGE-001|High|Vantage|Record differs between internal and external DNS|Align the internal zone (split DNS) before the cutover.'
        'VANTAGE-002|High|Vantage|Record present on one vantage only|Align the internal zone (split DNS) before the cutover.'
        'VANTAGE-003|Medium|Vantage|Query failed on one vantage only|Check resolver reachability and forwarding for that vantage.'
        'VANTAGE-004|Info|Vantage|Address records differ between vantages|Usually load balancing; check if the host is internal.'
        'VANTAGE-005|Medium|Vantage|SOA or NS differ between vantages (separate internal zone)|Keep the internal copy of the zone in sync during the cutover.'
    )
    $catalog = [ordered]@{}
    foreach ($row in $rows) {
        $p = $row -split '\|', 5
        $catalog[$p[0]] = [pscustomobject]@{ RuleId = $p[0]; Severity = $p[1]; Check = $p[2]; Title = $p[3]; Recommendation = $p[4] }
    }
    $catalog
}

function New-Finding {
    param(
        [Parameter(Mandatory = $true)][string]$RuleId,
        [string]$Domain,
        [string]$Target,
        [string]$Message,
        [string]$Recommendation
    )
    if (-not $script:RuleCatalog) { $script:RuleCatalog = Get-RuleCatalog }
    $rule = $script:RuleCatalog[$RuleId]
    if (-not $rule) { throw "Unknown rule id $RuleId" }
    if (-not $Target) { $Target = $Domain }
    if (-not $Message) { $Message = $rule.Title }
    if (-not $Recommendation) { $Recommendation = $rule.Recommendation }
    [pscustomobject]@{
        Domain         = $Domain
        RuleId         = $RuleId
        Severity       = $rule.Severity
        Check          = $rule.Check
        Vantage        = $null
        Target         = $Target
        Message        = $Message
        Recommendation = $Recommendation
    }
}

function Get-SeverityRank {
    param([string]$Severity)
    switch ($Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } default { 3 } }
}

function Merge-VantageFinding {
    # Findings with the same RuleId and Target on both vantages collapse into one with Vantage 'Both'.
    param([object[]]$Finding)
    $groups = [ordered]@{}
    foreach ($f in $Finding) {
        $key = '{0}|{1}' -f $f.RuleId, $f.Target
        if (-not $groups.Contains($key)) { $groups[$key] = [System.Collections.Generic.List[object]]::new() }
        $groups[$key].Add($f)
    }
    $merged = foreach ($key in $groups.Keys) {
        $items = $groups[$key]
        $vantages = @($items | ForEach-Object { $_.Vantage } | Where-Object { $_ } | Select-Object -Unique)
        $pick = @($items | Where-Object { $_.Vantage -eq 'External' })
        $first = if ($pick.Count -gt 0) { $pick[0] } else { $items[0] }
        $copy = $first.PSObject.Copy()
        if ($vantages.Count -gt 1) { $copy.Vantage = 'Both' }
        $copy
    }
    @($merged | Sort-Object @{ Expression = { Get-SeverityRank $_.Severity } }, RuleId, Target)
}

#endregion

#region Generic helpers

function ConvertTo-DnsName {
    param([string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return '' }
    $Name.Trim().TrimEnd('.').ToLowerInvariant()
}

function Test-ResolvedStatus {
    param([string]$Status)
    ($Status -eq 'NoError' -or $Status -eq 'NoData' -or $Status -eq 'NXDomain')
}

function Test-HostPattern {
    # RFC 8461 / RFC 6125 style: '*.example.com' matches exactly one extra label.
    param([string]$Pattern, [string]$HostName)
    $p = ConvertTo-DnsName $Pattern
    $h = ConvertTo-DnsName $HostName
    if (-not $p -or -not $h) { return $false }
    if ($p.StartsWith('*.')) {
        $suffix = $p.Substring(1)
        if (-not $h.EndsWith($suffix)) { return $false }
        $left = $h.Substring(0, $h.Length - $suffix.Length)
        return ($left.Length -gt 0 -and $left.IndexOf('.') -lt 0)
    }
    $p -eq $h
}

function Test-InDomain {
    param([string]$Name, [string]$Domain)
    $n = ConvertTo-DnsName $Name
    $d = ConvertTo-DnsName $Domain
    ($n -eq $d -or $n.EndsWith(".$d"))
}

function ConvertFrom-TagValueRecord {
    # Parses 'k=v; k=v' records (DMARC, DKIM, MTA-STS TXT, TLS-RPT). Keys are lower-cased.
    param([string]$Record)
    $tags = [ordered]@{}
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($part in ($Record -split ';')) {
        $t = $part.Trim()
        if (-not $t) { continue }
        $i = $t.IndexOf('=')
        if ($i -lt 1) { $errors.Add("Malformed tag '$t'"); continue }
        $k = $t.Substring(0, $i).Trim().ToLowerInvariant()
        $v = $t.Substring($i + 1).Trim()
        if ($tags.Contains($k)) { $errors.Add("Duplicate tag '$k'"); continue }
        $tags[$k] = $v
    }
    [pscustomobject]@{ Tags = $tags; Errors = @($errors) }
}

function Get-MxHostClass {
    param([string]$HostName, [string[]]$ScopeDomain)
    $h = ConvertTo-DnsName $HostName
    if ($h -match '\.mail\.protection\.(outlook\.com|office365\.us|partner\.outlook\.cn)$') { return 'EOP' }
    if ($h -match '\.mx\.microsoft$') { return 'EOP-DANE' }
    foreach ($d in $ScopeDomain) { if (Test-InDomain $h $d) { return 'OnPremises' } }
    'Other'
}

#endregion

#region DNS resolution

function Get-DnsTypeCode {
    param([string]$Type)
    $map = @{ A = 1; NS = 2; CNAME = 5; SOA = 6; PTR = 12; MX = 15; TXT = 16; AAAA = 28; SRV = 33; OPT = 41; DS = 43; RRSIG = 46; DNSKEY = 48; TLSA = 52; CAA = 257 }
    if (-not $map.ContainsKey($Type)) { throw "Unsupported record type $Type" }
    $map[$Type]
}

function Get-DnsTypeName {
    param([int]$Code)
    $map = @{ 1 = 'A'; 2 = 'NS'; 5 = 'CNAME'; 6 = 'SOA'; 12 = 'PTR'; 15 = 'MX'; 16 = 'TXT'; 28 = 'AAAA'; 33 = 'SRV'; 41 = 'OPT'; 43 = 'DS'; 46 = 'RRSIG'; 48 = 'DNSKEY'; 52 = 'TLSA'; 257 = 'CAA' }
    if ($map.ContainsKey($Code)) { return $map[$Code] }
    "TYPE$Code"
}

function New-DnsRecordObject {
    param([string]$Name, [string]$Type, $TTL, [string]$Data, $Preference, [string]$Target, $Priority, $Weight, $Port)
    [pscustomobject]@{
        Name       = ConvertTo-DnsName $Name
        Type       = $Type
        TTL        = $TTL
        Data       = $Data
        Preference = $Preference
        Target     = $Target
        Priority   = $Priority
        Weight     = $Weight
        Port       = $Port
    }
}

function ConvertFrom-DnsClientRecord {
    # Normalises a Resolve-DnsName output object.
    param($Record)
    $type = [string]$Record.Type
    if ($type -match '^\d+$') { $type = Get-DnsTypeName ([int]$type) }
    $ttl = [int]$Record.TTL
    switch ($type) {
        'A' { return New-DnsRecordObject -Name $Record.Name -Type $type -TTL $ttl -Data ([string]$Record.IPAddress) }
        'AAAA' { return New-DnsRecordObject -Name $Record.Name -Type $type -TTL $ttl -Data ([string]$Record.IPAddress) }
        'MX' {
            $t = ConvertTo-DnsName $Record.NameExchange
            return New-DnsRecordObject -Name $Record.Name -Type $type -TTL $ttl -Data ('{0} {1}' -f $Record.Preference, $t) -Preference ([int]$Record.Preference) -Target $t
        }
        'TXT' { return New-DnsRecordObject -Name $Record.Name -Type $type -TTL $ttl -Data (@($Record.Strings) -join '') }
        'SRV' {
            $t = ConvertTo-DnsName $Record.NameTarget
            return New-DnsRecordObject -Name $Record.Name -Type $type -TTL $ttl -Data ('{0} {1} {2} {3}' -f $Record.Priority, $Record.Weight, $Record.Port, $t) -Target $t -Priority ([int]$Record.Priority) -Weight ([int]$Record.Weight) -Port ([int]$Record.Port)
        }
        'SOA' { return New-DnsRecordObject -Name $Record.Name -Type $type -TTL $ttl -Data ('{0} {1} {2}' -f (ConvertTo-DnsName $Record.PrimaryServer), (ConvertTo-DnsName $Record.NameAdministrator), $Record.SerialNumber) }
        default {
            if ($type -in @('CNAME', 'NS', 'PTR')) {
                $t = ConvertTo-DnsName $Record.NameHost
                return New-DnsRecordObject -Name $Record.Name -Type $type -TTL $ttl -Data $t -Target $t
            }
            return New-DnsRecordObject -Name $Record.Name -Type $type -TTL $ttl -Data ''
        }
    }
}

function ConvertFrom-DnsClientError {
    # Maps a Resolve-DnsName error (FullyQualifiedErrorId / Win32 code) to a status.
    param([string]$ErrorId, [int]$NativeErrorCode)
    $id = if ($ErrorId) { ($ErrorId -split ',')[0] } else { '' }
    switch ($id) {
        'DNS_ERROR_RCODE_NAME_ERROR' { return 'NXDomain' }
        'DNS_INFO_NO_RECORDS' { return 'NoData' }
        'DNS_ERROR_RECORD_DOES_NOT_EXIST' { return 'NoData' }
        'DNS_ERROR_RCODE_SERVER_FAILURE' { return 'ServFail' }
        'DNS_ERROR_RCODE_REFUSED' { return 'Refused' }
        'ERROR_TIMEOUT' { return 'Timeout' }
        'WSAETIMEDOUT' { return 'Timeout' }
    }
    switch ($NativeErrorCode) {
        9003 { return 'NXDomain' }
        9501 { return 'NoData' }
        9701 { return 'NoData' }
        9002 { return 'ServFail' }
        9005 { return 'Refused' }
        1460 { return 'Timeout' }
        10060 { return 'Timeout' }
    }
    'Error'
}

function Invoke-DnsClientQuery {
    # Resolve-DnsName in a reusable runspace so a per-query timeout can be enforced.
    param([string]$Name, [string]$Type, [string]$Server, [int]$TimeoutSeconds)
    if (-not $script:DnsClientRunspace -or $script:DnsClientRunspace.RunspaceStateInfo.State -ne 'Opened') {
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        [void]$iss.ImportPSModule(@('DnsClient'))
        $script:DnsClientRunspace = [runspacefactory]::CreateRunspace($iss)
        $script:DnsClientRunspace.Open()
    }
    $ps = [powershell]::Create()
    $ps.Runspace = $script:DnsClientRunspace
    [void]$ps.AddCommand('Resolve-DnsName').AddParameter('Name', $Name).AddParameter('Type', $Type).AddParameter('Server', $Server).AddParameter('DnsOnly', $true).AddParameter('NoHostsFile', $true).AddParameter('ErrorAction', 'Continue')
    $handle = $ps.BeginInvoke()
    if (-not $handle.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) {
        # Abandon the busy runspace; a fresh one is created for the next query.
        [void]$ps.BeginStop($null, $null)
        $script:DnsClientRunspace = $null
        return [pscustomobject]@{ Status = 'Timeout'; Records = @(); Message = "No answer within $TimeoutSeconds s" }
    }
    try {
        $output = $ps.EndInvoke($handle)
        if ($ps.Streams.Error.Count -gt 0) {
            $err = $ps.Streams.Error[0]
            $native = 0
            $ex = $err.Exception
            if ($ex -is [System.ComponentModel.Win32Exception]) { $native = $ex.NativeErrorCode }
            $status = ConvertFrom-DnsClientError -ErrorId $err.FullyQualifiedErrorId -NativeErrorCode $native
            return [pscustomobject]@{ Status = $status; Records = @(); Message = $ex.Message }
        }
        $records = @($output | Where-Object { [string]$_.Section -eq 'Answer' } | ForEach-Object { ConvertFrom-DnsClientRecord $_ })
        [pscustomobject]@{ Status = 'NoError'; Records = $records; Message = $null }
    }
    catch {
        [pscustomobject]@{ Status = 'Error'; Records = @(); Message = $_.Exception.Message }
    }
    finally {
        $ps.Dispose()
    }
}

function New-DnsQueryPacket {
    # DNS query with EDNS0 (1232-byte payload). -DnssecOk sets DO and AD, -CheckingDisabled sets CD.
    param([string]$Name, [int]$TypeCode, [int]$Id, [switch]$DnssecOk, [switch]$CheckingDisabled)
    $b = [System.Collections.Generic.List[byte]]::new()
    $flags2 = 0
    if ($DnssecOk) { $flags2 = $flags2 -bor 0x20 }
    if ($CheckingDisabled) { $flags2 = $flags2 -bor 0x10 }
    $b.AddRange([byte[]]@((($Id -shr 8) -band 0xFF), ($Id -band 0xFF), 0x01, $flags2, 0, 1, 0, 0, 0, 0, 0, 1))
    foreach ($label in ((ConvertTo-DnsName $Name) -split '\.')) {
        if (-not $label) { continue }
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($label)
        if ($bytes.Length -gt 63) { throw "Label too long in $Name" }
        $b.Add([byte]$bytes.Length)
        $b.AddRange($bytes)
    }
    $b.Add(0)
    $b.AddRange([byte[]]@((($TypeCode -shr 8) -band 0xFF), ($TypeCode -band 0xFF), 0, 1))
    $doFlag = 0
    if ($DnssecOk) { $doFlag = 0x80 }
    $b.AddRange([byte[]]@(0, 0, 41, 0x04, 0xD0, 0, 0, $doFlag, 0, 0, 0))
    $b.ToArray()
}

function Read-DnsWireName {
    # Returns @(name, offsetAfterName); follows compression pointers.
    param([byte[]]$Bytes, [int]$Offset)
    $labels = [System.Collections.Generic.List[string]]::new()
    $pos = $Offset
    $next = -1
    $jumps = 0
    while ($true) {
        if ($pos -ge $Bytes.Length) { throw 'DNS name runs past the end of the message' }
        $len = [int]$Bytes[$pos]
        if ($len -eq 0) { $pos++; break }
        if (($len -band 0xC0) -eq 0xC0) {
            if ($next -lt 0) { $next = $pos + 2 }
            $pos = (($len -band 0x3F) -shl 8) -bor $Bytes[$pos + 1]
            $jumps++
            if ($jumps -gt 64) { throw 'DNS name compression loop' }
            continue
        }
        $labels.Add([System.Text.Encoding]::ASCII.GetString($Bytes, $pos + 1, $len))
        $pos += 1 + $len
    }
    if ($next -lt 0) { $next = $pos }
    @((($labels -join '.').ToLowerInvariant()), $next)
}

function Read-UInt16 { param([byte[]]$Bytes, [int]$Offset) ([int]$Bytes[$Offset] -shl 8) -bor $Bytes[$Offset + 1] }

function Read-UInt32 { param([byte[]]$Bytes, [int]$Offset) [int64]$Bytes[$Offset] * 16777216 + [int64]$Bytes[$Offset + 1] * 65536 + [int64]$Bytes[$Offset + 2] * 256 + $Bytes[$Offset + 3] }

function ConvertFrom-DnsWireMessage {
    param([byte[]]$Bytes)
    if ($Bytes.Length -lt 12) { throw 'DNS response shorter than a header' }
    $qd = Read-UInt16 $Bytes 4
    $an = Read-UInt16 $Bytes 6
    $pos = 12
    for ($i = 0; $i -lt $qd; $i++) { $pos = (Read-DnsWireName $Bytes $pos)[1] + 4 }
    $answers = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $an; $i++) {
        $n = Read-DnsWireName $Bytes $pos
        $pos = $n[1]
        $typeName = Get-DnsTypeName (Read-UInt16 $Bytes $pos)
        $ttl = Read-UInt32 $Bytes ($pos + 4)
        $rdlen = Read-UInt16 $Bytes ($pos + 8)
        $rd = $pos + 10
        $pos = $rd + $rdlen
        if ($pos -gt $Bytes.Length) { throw 'DNS record runs past the end of the message' }
        $rec = $null
        switch ($typeName) {
            'A' { $rec = New-DnsRecordObject -Name $n[0] -Type 'A' -TTL $ttl -Data ([System.Net.IPAddress]::new([byte[]]$Bytes[$rd..($rd + 3)])).ToString() }
            'AAAA' { $rec = New-DnsRecordObject -Name $n[0] -Type 'AAAA' -TTL $ttl -Data ([System.Net.IPAddress]::new([byte[]]$Bytes[$rd..($rd + 15)])).ToString() }
            'MX' {
                $pref = Read-UInt16 $Bytes $rd
                $t = (Read-DnsWireName $Bytes ($rd + 2))[0]
                $rec = New-DnsRecordObject -Name $n[0] -Type 'MX' -TTL $ttl -Data "$pref $t" -Preference $pref -Target $t
            }
            'TXT' {
                $sb = New-Object System.Text.StringBuilder
                $j = $rd
                while ($j -lt $rd + $rdlen) {
                    $l = [int]$Bytes[$j]
                    [void]$sb.Append([System.Text.Encoding]::UTF8.GetString($Bytes, $j + 1, $l))
                    $j += 1 + $l
                }
                $rec = New-DnsRecordObject -Name $n[0] -Type 'TXT' -TTL $ttl -Data $sb.ToString()
            }
            'SRV' {
                $t = (Read-DnsWireName $Bytes ($rd + 6))[0]
                $pri = Read-UInt16 $Bytes $rd; $wt = Read-UInt16 $Bytes ($rd + 2); $port = Read-UInt16 $Bytes ($rd + 4)
                $rec = New-DnsRecordObject -Name $n[0] -Type 'SRV' -TTL $ttl -Data "$pri $wt $port $t" -Target $t -Priority $pri -Weight $wt -Port $port
            }
            'SOA' {
                $m = Read-DnsWireName $Bytes $rd
                $r = Read-DnsWireName $Bytes $m[1]
                $serial = Read-UInt32 $Bytes $r[1]
                $rec = New-DnsRecordObject -Name $n[0] -Type 'SOA' -TTL $ttl -Data ('{0} {1} {2}' -f $m[0], $r[0], $serial)
            }
            'TLSA' {
                $hex = ''
                if ($rdlen -gt 3) { $hex = (($Bytes[($rd + 3)..($rd + $rdlen - 1)] | ForEach-Object { $_.ToString('x2') }) -join '') }
                $rec = New-DnsRecordObject -Name $n[0] -Type 'TLSA' -TTL $ttl -Data ('{0} {1} {2} {3}' -f $Bytes[$rd], $Bytes[$rd + 1], $Bytes[$rd + 2], $hex)
            }
            'RRSIG' { $rec = New-DnsRecordObject -Name $n[0] -Type 'RRSIG' -TTL $ttl -Data ('covers ' + (Get-DnsTypeName (Read-UInt16 $Bytes $rd))) }
            default {
                if ($typeName -in @('CNAME', 'NS', 'PTR')) {
                    $t = (Read-DnsWireName $Bytes $rd)[0]
                    $rec = New-DnsRecordObject -Name $n[0] -Type $typeName -TTL $ttl -Data $t -Target $t
                }
                else { $rec = New-DnsRecordObject -Name $n[0] -Type $typeName -TTL $ttl -Data '' }
            }
        }
        $answers.Add($rec)
    }
    [pscustomobject]@{
        Id                 = Read-UInt16 $Bytes 0
        Truncated          = [bool]($Bytes[2] -band 0x02)
        RecursionAvailable = [bool]($Bytes[3] -band 0x80)
        AuthenticData      = [bool]($Bytes[3] -band 0x20)
        Rcode              = [int]($Bytes[3] -band 0x0F)
        Answers            = @($answers)
    }
}

function Resolve-ServerAddress {
    param([string]$Server)
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($Server, [ref]$ip)) { return $ip }
    @([System.Net.Dns]::GetHostAddresses($Server))[0]
}

function Invoke-DnsWireQuery {
    # Direct UDP (TCP on truncation) query; exposes AD flag, RRSIG presence and TLSA.
    param([string]$Name, [string]$Type, [string]$Server, [int]$TimeoutSeconds = 5, [switch]$DnssecOk, [switch]$CheckingDisabled)
    $id = Get-Random -Minimum 1 -Maximum 65535
    $query = New-DnsQueryPacket -Name $Name -TypeCode (Get-DnsTypeCode $Type) -Id $id -DnssecOk:$DnssecOk -CheckingDisabled:$CheckingDisabled
    $msg = $null
    try {
        $ip = Resolve-ServerAddress $Server
        $udp = New-Object System.Net.Sockets.UdpClient($ip.AddressFamily)
        try {
            $udp.Client.ReceiveTimeout = $TimeoutSeconds * 1000
            $udp.Connect($ip, 53)
            [void]$udp.Send($query, $query.Length)
            $remote = New-Object System.Net.IPEndPoint($ip, 0)
            for ($try = 0; $try -lt 5; $try++) {
                $msg = ConvertFrom-DnsWireMessage ($udp.Receive([ref]$remote))
                if ($msg.Id -eq $id) { break }
                $msg = $null
            }
        }
        finally { $udp.Close() }
        if ($msg -and $msg.Truncated) {
            $tcp = New-Object System.Net.Sockets.TcpClient($ip.AddressFamily)
            try {
                $ar = $tcp.BeginConnect($ip, 53, $null, $null)
                if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) { throw 'TCP connect timed out' }
                $tcp.EndConnect($ar)
                $tcp.ReceiveTimeout = $TimeoutSeconds * 1000
                $stream = $tcp.GetStream()
                $framed = [byte[]](@([byte](($query.Length -shr 8) -band 0xFF), [byte]($query.Length -band 0xFF)) + $query)
                $stream.Write($framed, 0, $framed.Length)
                $lenBuf = New-Object byte[] 2
                $got = 0
                while ($got -lt 2) { $r = $stream.Read($lenBuf, $got, 2 - $got); if ($r -le 0) { throw 'TCP connection closed' }; $got += $r }
                $len = ([int]$lenBuf[0] -shl 8) -bor $lenBuf[1]
                $buf = New-Object byte[] $len
                $got = 0
                while ($got -lt $len) { $r = $stream.Read($buf, $got, $len - $got); if ($r -le 0) { throw 'TCP connection closed' }; $got += $r }
                $msg = ConvertFrom-DnsWireMessage $buf
            }
            finally { $tcp.Close() }
        }
    }
    catch {
        $base = $_.Exception.GetBaseException()
        $status = 'Error'
        if ($base -is [System.Net.Sockets.SocketException] -and $base.SocketErrorCode -in @('TimedOut', 'WouldBlock')) { $status = 'Timeout' }
        return [pscustomobject]@{ Status = $status; Records = @(); Authenticated = $null; Signed = $null; Message = $base.Message }
    }
    if (-not $msg) { return [pscustomobject]@{ Status = 'Error'; Records = @(); Authenticated = $null; Signed = $null; Message = 'No matching response' } }
    $status = switch ($msg.Rcode) { 0 { 'NoError' } 2 { 'ServFail' } 3 { 'NXDomain' } 5 { 'Refused' } default { "Rcode$($msg.Rcode)" } }
    $records = @($msg.Answers | Where-Object { $_.Type -ne 'RRSIG' -and $_.Type -ne 'OPT' })
    $signed = @($msg.Answers | Where-Object { $_.Type -eq 'RRSIG' }).Count -gt 0
    [pscustomobject]@{ Status = $status; Records = $records; Authenticated = $msg.AuthenticData; Signed = $signed; Message = $null }
}

function Resolve-Record {
    # Resolver selection (failover in order, unhealthy last), timeout, TTL capture, DNSSEC flag,
    # status normalisation, per-run cache and per-domain query log.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Type,
        [Parameter(Mandatory = $true)][hashtable]$Context,
        [switch]$DnssecOk,
        [switch]$CheckingDisabled
    )
    $Name = ConvertTo-DnsName $Name
    $key = '{0}|{1}|{2}|{3}|{4}' -f $Context.Vantage, $Name, $Type, [bool]$DnssecOk, [bool]$CheckingDisabled
    if ($Context.Cache.ContainsKey($key)) {
        $result = $Context.Cache[$key]
    }
    else {
        $useWire = $DnssecOk -or $CheckingDisabled -or $Type -eq 'TLSA' -or $Context.Engine -eq 'Wire'
        $good = @($Context.Resolvers | Where-Object { -not $Context.Health.ContainsKey($_) -or $Context.Health[$_] -lt 2 })
        $bad = @($Context.Resolvers | Where-Object { $Context.Health.ContainsKey($_) -and $Context.Health[$_] -ge 2 })
        $raw = $null
        $server = $null
        foreach ($server in ($good + $bad)) {
            if ($useWire) {
                $raw = Invoke-DnsWireQuery -Name $Name -Type $Type -Server $server -TimeoutSeconds $Context.TimeoutSeconds -DnssecOk:$DnssecOk -CheckingDisabled:$CheckingDisabled
            }
            else {
                $raw = Invoke-DnsClientQuery -Name $Name -Type $Type -Server $server -TimeoutSeconds $Context.TimeoutSeconds
            }
            Write-Verbose ('[{0}] {1} {2} @{3} -> {4} ({5} record(s))' -f $Context.Vantage, $Name, $Type, $server, $raw.Status, @($raw.Records).Count)
            if ($raw.Status -eq 'Timeout') { $Context.Health[$server] = 1 + [int]$Context.Health[$server] } else { $Context.Health[$server] = 0 }
            if (Test-ResolvedStatus $raw.Status) { break }
        }
        $records = @($raw.Records | Where-Object { $_ })
        $status = $raw.Status
        if ($status -eq 'NoError' -and @($records | Where-Object { $_.Type -eq $Type }).Count -eq 0) { $status = 'NoData' }
        $auth = $null
        $signed = $null
        if ($raw.PSObject.Properties['Authenticated']) { $auth = $raw.Authenticated; $signed = $raw.Signed }
        $result = [pscustomobject]@{
            Vantage       = $Context.Vantage
            Name          = $Name
            Type          = $Type
            DnssecOk      = [bool]$DnssecOk
            CheckingDisabled = [bool]$CheckingDisabled
            Resolver      = $server
            Engine        = $(if ($useWire) { 'Wire' } else { 'DnsClient' })
            Status        = $status
            Records       = $records
            Authenticated = $auth
            Signed        = $signed
            Message       = $raw.Message
        }
        $Context.Cache[$key] = $result
    }
    if ($null -ne $Context.Log) { $Context.Log.Add($result) }
    $result
}

function Get-AnswerRecord {
    param($Result, [string]$Type)
    @($Result.Records | Where-Object { $_.Type -eq $Type })
}

function Get-SystemDnsResolver {
    $list = @()
    if (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue) {
        $list = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
    }
    elseif (Test-Path '/etc/resolv.conf') {
        $list = @(Get-Content '/etc/resolv.conf' | Where-Object { $_ -match '^\s*nameserver\s+(\S+)' } | ForEach-Object { ($_ -split '\s+')[1] })
    }
    @($list | Where-Object { $_ -and $_ -notlike 'fec0:*' } | Select-Object -Unique)
}

#endregion

#region MX

function Get-MxAssessment {
    param([string]$Domain, [hashtable]$Context, [string[]]$ScopeDomain)
    $findings = [System.Collections.Generic.List[object]]::new()
    $r = Resolve-Record -Name $Domain -Type MX -Context $Context
    $mx = @(Get-AnswerRecord $r 'MX' | Sort-Object Preference, Target)
    $hosts = [System.Collections.Generic.List[object]]::new()
    $class = 'Unknown'
    $ttl = $null
    $nullMx = $false
    if (Test-ResolvedStatus $r.Status) {
        if ($mx.Count -eq 0) {
            $class = 'None'
            $findings.Add((New-Finding -RuleId 'MX-001' -Domain $Domain))
        }
        elseif ($mx.Count -eq 1 -and -not $mx[0].Target) {
            $class = 'NullMX'
            $nullMx = $true
            $findings.Add((New-Finding -RuleId 'MX-008' -Domain $Domain))
        }
        else {
            $ttl = [int]($mx | Measure-Object -Property TTL -Minimum).Minimum
            foreach ($m in $mx) {
                if (-not $m.Target) { continue }
                $a = Resolve-Record -Name $m.Target -Type A -Context $Context
                $aaaa = Resolve-Record -Name $m.Target -Type AAAA -Context $Context
                $cname = @(Get-AnswerRecord $a 'CNAME' | Where-Object { $_.Name -eq $m.Target })
                $v4 = @(Get-AnswerRecord $a 'A' | ForEach-Object { $_.Data })
                $v6 = @(Get-AnswerRecord $aaaa 'AAAA' | ForEach-Object { $_.Data })
                $hc = Get-MxHostClass -HostName $m.Target -ScopeDomain $ScopeDomain
                $hosts.Add([pscustomobject]@{
                        Preference  = $m.Preference
                        Host        = $m.Target
                        TTL         = $m.TTL
                        Class       = $hc
                        CnameTarget = $(if ($cname.Count) { $cname[0].Target } else { $null })
                        IPv4        = $v4
                        IPv6        = $v6
                        Resolver    = $a.Resolver
                    })
                if ($cname.Count) { $findings.Add((New-Finding -RuleId 'MX-003' -Domain $Domain -Target $m.Target -Message "MX host $($m.Target) is a CNAME to $($cname[0].Target)")) }
                if (($v4.Count + $v6.Count) -eq 0 -and (Test-ResolvedStatus $a.Status) -and (Test-ResolvedStatus $aaaa.Status)) {
                    $findings.Add((New-Finding -RuleId 'MX-006' -Domain $Domain -Target $m.Target -Message "MX host $($m.Target) has no A or AAAA record ($($a.Status))"))
                }
            }
            $classes = @($hosts | ForEach-Object { $_.Class } | Select-Object -Unique)
            $ms = @($classes | Where-Object { $_ -like 'EOP*' })
            $other = @($classes | Where-Object { $_ -notlike 'EOP*' })
            if ($ms.Count -and $other.Count) {
                $class = 'Mixed'
                $names = ($hosts | Where-Object { $_.Class -notlike 'EOP*' } | ForEach-Object { $_.Host }) -join ', '
                $findings.Add((New-Finding -RuleId 'MX-002' -Domain $Domain -Message "EOP and non-Microsoft MX hosts published together: $names"))
            }
            elseif ($ms.Count) { $class = ($ms | Sort-Object) -join '+' }
            else {
                $class = ($other | Sort-Object) -join '+'
                $findings.Add((New-Finding -RuleId 'MX-007' -Domain $Domain -Message ('MX points to ' + (($hosts | ForEach-Object { $_.Host }) -join ', '))))
            }
            if ($classes -contains 'EOP' -and $classes -notcontains 'EOP-DANE') { $findings.Add((New-Finding -RuleId 'MX-009' -Domain $Domain)) }
            if ($classes -contains 'EOP' -and $classes -contains 'EOP-DANE') { $findings.Add((New-Finding -RuleId 'MX-010' -Domain $Domain)) }
            if ($ttl -gt 3600) { $findings.Add((New-Finding -RuleId 'MX-004' -Domain $Domain -Message "MX TTL is $ttl seconds")) }
            elseif ($ttl -lt 300) { $findings.Add((New-Finding -RuleId 'MX-005' -Domain $Domain -Message "MX TTL is $ttl seconds")) }
        }
    }
    [pscustomobject]@{
        Status   = $r.Status
        Resolver = $r.Resolver
        TTL      = $ttl
        Class    = $class
        NullMx   = $nullMx
        Hosts    = @($hosts)
        Findings = @($findings)
    }
}

#endregion

#region SPF

function ConvertFrom-SpfRecord {
    # Parses one SPF record into terms. No DNS.
    param([string]$Record)
    $terms = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $tokens = @($Record.Trim() -split '\s+' | Where-Object { $_ })
    if ($tokens.Count -eq 0 -or $tokens[0] -ne 'v=spf1') { $errors.Add('Record does not start with v=spf1') }
    $lookupMechanisms = @('include', 'a', 'mx', 'ptr', 'exists')
    for ($i = 1; $i -lt $tokens.Count; $i++) {
        $t = $tokens[$i]
        if ($t -match '^(?<name>[A-Za-z][A-Za-z0-9_.\-]*)=(?<value>.*)$') {
            $name = $Matches['name'].ToLowerInvariant()
            $value = $Matches['value']
            if ($name -in @('redirect', 'exp') -and -not $value) { $errors.Add("Modifier '$t' has no domain") }
            $terms.Add([pscustomobject]@{ Kind = 'Modifier'; Qualifier = ''; Name = $name; Value = $value; Cidr = $null; Raw = $t; Lookup = ($name -eq 'redirect'); HasMacro = ($value -match '%\{') })
            continue
        }
        if ($t -notmatch '^(?<q>[+\-~?]?)(?<m>[A-Za-z][A-Za-z0-9]*)(?<rest>[:/].*)?$') { $errors.Add("Invalid term '$t'"); continue }
        $q = if ($Matches['q']) { $Matches['q'] } else { '+' }
        $m = $Matches['m'].ToLowerInvariant()
        $rest = [string]$Matches['rest']
        $value = $null
        $cidr = $null
        switch ($m) {
            'all' { if ($rest) { $errors.Add("'all' takes no argument: '$t'") } }
            { $_ -in @('ip4', 'ip6') } {
                if (-not $rest.StartsWith(':')) { $errors.Add("Missing address in '$t'"); break }
                $value = $rest.Substring(1)
                $addr = ($value -split '/')[0]
                $len = if ($value.Contains('/')) { ($value -split '/', 2)[1] } else { $null }
                $ip = $null
                $family = if ($m -eq 'ip4') { 'InterNetwork' } else { 'InterNetworkV6' }
                $max = if ($m -eq 'ip4') { 32 } else { 128 }
                $okAddr = [System.Net.IPAddress]::TryParse($addr, [ref]$ip) -and $ip.AddressFamily.ToString() -eq $family
                if ($m -eq 'ip4' -and $addr -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { $okAddr = $false }
                $okLen = ($null -eq $len) -or ($len -match '^\d{1,3}$' -and [int]$len -le $max)
                if (-not ($okAddr -and $okLen)) { $errors.Add("Invalid address in '$t'") }
                $cidr = $len
            }
            { $_ -in @('include', 'exists') } {
                if (-not $rest.StartsWith(':') -or $rest.Length -lt 2) { $errors.Add("Missing domain in '$t'"); break }
                $value = $rest.Substring(1)
            }
            { $_ -in @('a', 'mx', 'ptr') } {
                if ($rest.StartsWith(':')) {
                    $spec = $rest.Substring(1)
                    $slash = $spec.IndexOf('/')
                    if ($slash -ge 0) { $value = $spec.Substring(0, $slash); $cidr = $spec.Substring($slash + 1) } else { $value = $spec }
                    if (-not $value) { $errors.Add("Missing domain in '$t'") }
                }
                elseif ($rest) { $cidr = $rest.Substring(1) }
                if ($cidr -and $cidr -notmatch '^\d{1,3}(//\d{1,3})?$|^/\d{1,3}$') { $errors.Add("Invalid prefix length in '$t'") }
            }
            default { $errors.Add("Unknown mechanism '$t'") }
        }
        $terms.Add([pscustomobject]@{ Kind = 'Mechanism'; Qualifier = $q; Name = $m; Value = $value; Cidr = $cidr; Raw = $t; Lookup = ($m -in $lookupMechanisms); HasMacro = ([string]$value -match '%\{') })
    }
    [pscustomobject]@{ Valid = ($errors.Count -eq 0); Terms = @($terms); Errors = @($errors) }
}

function Get-SpfRecordFromTxt {
    param([object[]]$Txt)
    @($Txt | Where-Object { $_.Data -match '^\s*v=spf1(\s|$)' } | ForEach-Object { $_.Data.Trim() })
}

function Expand-SpfRecord {
    # Recursive expansion with RFC 7208 lookup and void-lookup accounting.
    param([string]$Name, [hashtable]$Context, [hashtable]$State, [int]$Depth, [string]$Path)
    $r = Resolve-Record -Name $Name -Type TXT -Context $Context
    $spf = @(Get-SpfRecordFromTxt (Get-AnswerRecord $r 'TXT'))
    $node = [ordered]@{ Domain = $Name; Depth = $Depth; Status = $r.Status; Record = $null; All = $null; EffectiveAll = $null; NoRecord = $false }
    if ($r.Status -eq 'NXDomain' -or $r.Status -eq 'NoData') { $State.VoidLookups++ }
    if ($spf.Count -eq 0) { $node.NoRecord = $true; return [pscustomobject]$node }
    if ($spf.Count -gt 1) { $State.Problems.Add([pscustomobject]@{ RuleId = 'SPF-002'; Target = $Name; Message = "$($spf.Count) SPF records at $Name" }) }
    $node.Record = $spf[0]
    $parsed = ConvertFrom-SpfRecord $spf[0]
    foreach ($e in $parsed.Errors) { $State.Problems.Add([pscustomobject]@{ RuleId = 'SPF-015'; Target = $Name; Message = "$Name : $e" }) }
    $redirect = $null
    $hasAll = @($parsed.Terms | Where-Object { $_.Kind -eq 'Mechanism' -and $_.Name -eq 'all' }).Count -gt 0
    foreach ($t in $parsed.Terms) {
        $counted = $t.Lookup -and -not ($t.Name -eq 'redirect' -and $hasAll)
        $State.Terms.Add([pscustomobject]@{ Source = $Name; Path = $Path; Depth = $Depth; Kind = $t.Kind; Qualifier = $t.Qualifier; Mechanism = $t.Name; Value = $t.Value; Raw = $t.Raw; CountsLookup = $counted })
        if ($counted) { $State.Lookups++ }
        if ($t.HasMacro) { $State.Macros.Add($t.Raw); continue }
        if ($t.Kind -eq 'Modifier') {
            if ($t.Name -eq 'redirect' -and -not $hasAll) { $redirect = ConvertTo-DnsName $t.Value }
            continue
        }
        switch ($t.Name) {
            'all' { $node.All = $t.Qualifier }
            'ip4' { $State.Ips.Add([pscustomobject]@{ Source = $Name; Qualifier = $t.Qualifier; Family = 'IPv4'; Range = $t.Value }) }
            'ip6' { $State.Ips.Add([pscustomobject]@{ Source = $Name; Qualifier = $t.Qualifier; Family = 'IPv6'; Range = $t.Value }) }
            'ptr' { $State.Ptr.Add($Name) }
            'include' {
                $target = ConvertTo-DnsName $t.Value
                if ($target -eq 'spf.protection.outlook.com' -or $target -eq 'spf.protection.office365.us') { $State.Eop = $true }
                if ($State.Chain -contains $target) { $State.Problems.Add([pscustomobject]@{ RuleId = 'SPF-017'; Target = $target; Message = "Include loop: $Path > $target" }); break }
                if ($Depth -ge 10) { break }
                $State.Chain.Add($target)
                $child = Expand-SpfRecord -Name $target -Context $Context -State $State -Depth ($Depth + 1) -Path "$Path > $target"
                $State.Chain.RemoveAt($State.Chain.Count - 1)
                if ($child.NoRecord -and (Test-ResolvedStatus $child.Status)) {
                    $State.Problems.Add([pscustomobject]@{ RuleId = 'SPF-010'; Target = $target; Message = "include:$target in $Name returns no SPF record ($($child.Status))" })
                }
            }
            { $_ -in @('a', 'mx', 'exists') } {
                $mech = $t.Name
                if ($mech -ne 'exists') { $State.AMx.Add($t.Raw) }
                $target = if ($t.Value) { ConvertTo-DnsName $t.Value } else { $Name }
                $qt = if ($mech -eq 'mx') { 'MX' } else { 'A' }
                $q = Resolve-Record -Name $target -Type $qt -Context $Context
                if ($q.Status -eq 'NoData' -and $mech -eq 'a') { $q = Resolve-Record -Name $target -Type AAAA -Context $Context }
                if ($q.Status -eq 'NXDomain' -or $q.Status -eq 'NoData') { $State.VoidLookups++ }
                if ($mech -eq 'mx' -and @(Get-AnswerRecord $q 'MX').Count -gt 10) { $State.Problems.Add([pscustomobject]@{ RuleId = 'SPF-015'; Target = $target; Message = "mx mechanism at $target returns more than 10 MX names" }) }
            }
        }
    }
    $node.EffectiveAll = $node.All
    if ($redirect) {
        if ($State.Chain -contains $redirect) {
            $State.Problems.Add([pscustomobject]@{ RuleId = 'SPF-017'; Target = $redirect; Message = "Redirect loop: $Path > $redirect" })
        }
        else {
            if ($redirect -eq 'spf.protection.outlook.com') { $State.Eop = $true }
            $State.Chain.Add($redirect)
            $child = Expand-SpfRecord -Name $redirect -Context $Context -State $State -Depth ($Depth + 1) -Path "$Path > redirect $redirect"
            $State.Chain.RemoveAt($State.Chain.Count - 1)
            if ($child.NoRecord -and (Test-ResolvedStatus $child.Status)) {
                $State.Problems.Add([pscustomobject]@{ RuleId = 'SPF-010'; Target = $redirect; Message = "redirect=$redirect in $Name returns no SPF record ($($child.Status))" })
            }
            $node.EffectiveAll = $child.EffectiveAll
        }
    }
    [pscustomobject]$node
}

function New-SpfState {
    param([string]$Root)
    $chain = [System.Collections.Generic.List[string]]::new()
    $chain.Add($Root)
    @{
        Lookups = 0; VoidLookups = 0; Eop = $false; Chain = $chain
        Terms = [System.Collections.Generic.List[object]]::new()
        Ips = [System.Collections.Generic.List[object]]::new()
        Problems = [System.Collections.Generic.List[object]]::new()
        Macros = [System.Collections.Generic.List[string]]::new()
        Ptr = [System.Collections.Generic.List[string]]::new()
        AMx = [System.Collections.Generic.List[string]]::new()
    }
}

function Get-SpfAssessment {
    param([string]$Domain, [hashtable]$Context)
    $findings = [System.Collections.Generic.List[object]]::new()
    $r = Resolve-Record -Name $Domain -Type TXT -Context $Context
    $records = @(Get-SpfRecordFromTxt (Get-AnswerRecord $r 'TXT'))
    $out = [ordered]@{
        Status = $r.Status; Resolver = $r.Resolver; Records = $records; Record = $null; Lookups = $null; VoidLookups = $null
        All = $null; IncludesEop = $false; ProjectedLookupsWithEop = $null; NonSending = $false; Terms = @(); IpRanges = @(); Findings = $null
    }
    if (-not (Test-ResolvedStatus $r.Status)) { $out.Findings = @(); return [pscustomobject]$out }
    if ($records.Count -eq 0) {
        $findings.Add((New-Finding -RuleId 'SPF-001' -Domain $Domain))
        $out.Findings = @($findings)
        return [pscustomobject]$out
    }
    if ($records.Count -gt 1) { $findings.Add((New-Finding -RuleId 'SPF-002' -Domain $Domain -Message "$($records.Count) v=spf1 records published")) }
    $state = New-SpfState -Root $Domain
    $root = Expand-SpfRecord -Name $Domain -Context $Context -State $state -Depth 0 -Path $Domain
    $out.Record = $root.Record
    $out.Lookups = $state.Lookups
    $out.VoidLookups = $state.VoidLookups
    $out.All = $root.EffectiveAll
    $out.IncludesEop = $state.Eop
    $out.Terms = @($state.Terms)
    $out.IpRanges = @($state.Ips)
    $topTerms = @($state.Terms | Where-Object { $_.Depth -eq 0 })
    $out.NonSending = ($topTerms.Count -eq 1 -and $topTerms[0].Mechanism -eq 'all' -and $topTerms[0].Qualifier -eq '-')

    foreach ($p in $state.Problems) {
        if ($p.RuleId -eq 'SPF-002' -and $p.Target -eq $Domain) { continue }
        $findings.Add((New-Finding -RuleId $p.RuleId -Domain $Domain -Target $p.Target -Message $p.Message))
    }
    if ($state.Lookups -gt 10) { $findings.Add((New-Finding -RuleId 'SPF-003' -Domain $Domain -Message "$($state.Lookups) DNS-querying terms after expansion (limit 10)")) }
    elseif ($state.Lookups -ge 8) { $findings.Add((New-Finding -RuleId 'SPF-004' -Domain $Domain -Message "$($state.Lookups) DNS-querying terms after expansion (limit 10)")) }
    if ($state.VoidLookups -gt 2) { $findings.Add((New-Finding -RuleId 'SPF-005' -Domain $Domain -Message "$($state.VoidLookups) void lookups (limit 2)")) }
    if (-not $root.EffectiveAll) { $findings.Add((New-Finding -RuleId 'SPF-007' -Domain $Domain)) }
    elseif ($root.EffectiveAll -eq '+') { $findings.Add((New-Finding -RuleId 'SPF-006' -Domain $Domain)) }
    elseif ($root.EffectiveAll -eq '?') { $findings.Add((New-Finding -RuleId 'SPF-016' -Domain $Domain)) }
    elseif ($root.EffectiveAll -eq '~') { $findings.Add((New-Finding -RuleId 'SPF-018' -Domain $Domain)) }
    foreach ($p in ($state.Ptr | Select-Object -Unique)) { $findings.Add((New-Finding -RuleId 'SPF-008' -Domain $Domain -Target $p -Message "ptr mechanism in the record of $p")) }
    if ($state.AMx.Count) { $findings.Add((New-Finding -RuleId 'SPF-009' -Domain $Domain -Message ('a/mx mechanisms: ' + (($state.AMx | Select-Object -Unique) -join ' ')))) }
    if ($state.Macros.Count) { $findings.Add((New-Finding -RuleId 'SPF-014' -Domain $Domain -Message ('Macro terms: ' + (($state.Macros | Select-Object -Unique) -join ' ')))) }
    if ($state.Eop) { $findings.Add((New-Finding -RuleId 'SPF-011' -Domain $Domain)) }
    elseif (-not $out.NonSending) {
        $findings.Add((New-Finding -RuleId 'SPF-012' -Domain $Domain))
        # Project the cost of adding the EOP include without logging it as a domain record.
        $probeCtx = $Context.Clone()
        $probeCtx.Log = $null
        $probe = New-SpfState -Root 'spf.protection.outlook.com'
        [void](Expand-SpfRecord -Name 'spf.protection.outlook.com' -Context $probeCtx -State $probe -Depth 1 -Path 'spf.protection.outlook.com')
        $out.ProjectedLookupsWithEop = $state.Lookups + 1 + $probe.Lookups
        if ($out.ProjectedLookupsWithEop -gt 10 -and $state.Lookups -le 10) {
            $findings.Add((New-Finding -RuleId 'SPF-013' -Domain $Domain -Message "Lookups would rise from $($state.Lookups) to $($out.ProjectedLookupsWithEop)"))
        }
    }
    $out.Findings = @($findings)
    [pscustomobject]$out
}

#endregion

#region DKIM

function Read-DerElement {
    param([byte[]]$Bytes, [int]$Offset)
    if ($Offset + 2 -gt $Bytes.Length) { throw 'DER element truncated' }
    $tag = [int]$Bytes[$Offset]
    $lb = [int]$Bytes[$Offset + 1]
    $hdr = 2
    $len = $lb
    if ($lb -ge 0x80) {
        $n = $lb -band 0x7F
        if ($n -lt 1 -or $n -gt 4) { throw 'Unsupported DER length' }
        $len = 0
        for ($i = 0; $i -lt $n; $i++) { $len = $len * 256 + $Bytes[$Offset + 2 + $i] }
        $hdr = 2 + $n
    }
    if ($Offset + $hdr + $len -gt $Bytes.Length) { throw 'DER element truncated' }
    [pscustomobject]@{ Tag = $tag; Content = $Offset + $hdr; Length = $len; End = $Offset + $hdr + $len }
}

function Get-RsaModulusFromDer {
    # Manual ASN.1 DER walk: SPKI SEQUENCE -> AlgorithmIdentifier -> BIT STRING -> SEQUENCE -> INTEGER,
    # or a bare PKCS#1 RSAPublicKey SEQUENCE -> INTEGER. Works on .NET Framework and .NET.
    param([byte[]]$Bytes)
    $outer = Read-DerElement $Bytes 0
    if ($outer.Tag -ne 0x30) { throw 'Key is not a DER SEQUENCE' }
    $first = Read-DerElement $Bytes $outer.Content
    $format = 'PKCS1'
    $pkcs1Offset = 0
    if ($first.Tag -eq 0x30) {
        $format = 'SPKI'
        $oid = Read-DerElement $Bytes $first.Content
        if ($oid.Tag -ne 0x06) { throw 'AlgorithmIdentifier without OID' }
        $oidHex = (($Bytes[$oid.Content..($oid.End - 1)] | ForEach-Object { $_.ToString('x2') }) -join '')
        if ($oidHex -eq '2b6570') { return [pscustomobject]@{ Algorithm = 'Ed25519'; Format = $format; Bits = 256; Pkcs1 = $null } }
        if ($oidHex -ne '2a864886f70d010101') { return [pscustomobject]@{ Algorithm = "OID:$oidHex"; Format = $format; Bits = $null; Pkcs1 = $null } }
        $bitString = Read-DerElement $Bytes $first.End
        if ($bitString.Tag -ne 0x03 -or $Bytes[$bitString.Content] -ne 0) { throw 'Malformed BIT STRING' }
        $pkcs1Offset = $bitString.Content + 1
        $seq = Read-DerElement $Bytes $pkcs1Offset
        if ($seq.Tag -ne 0x30) { throw 'RSAPublicKey is not a SEQUENCE' }
        $modulus = Read-DerElement $Bytes $seq.Content
        $pkcs1End = $seq.End
    }
    elseif ($first.Tag -eq 0x02) {
        $modulus = $first
        $pkcs1End = $outer.End
    }
    else { throw 'Unrecognised key structure' }
    if ($modulus.Tag -ne 0x02) { throw 'Modulus is not an INTEGER' }
    $i = $modulus.Content
    while ($i -lt $modulus.End -and $Bytes[$i] -eq 0) { $i++ }
    $bits = 0
    if ($i -lt $modulus.End) {
        $bits = ($modulus.End - $i - 1) * 8
        $b = [int]$Bytes[$i]
        while ($b -gt 0) { $bits++; $b = $b -shr 1 }
    }
    $pkcs1 = [byte[]]$Bytes[$pkcs1Offset..($pkcs1End - 1)]
    [pscustomobject]@{ Algorithm = 'RSA'; Format = $format; Bits = $bits; Pkcs1 = $pkcs1 }
}

function Get-RsaKeySizePlatform {
    # Cross-check with the platform API: RSA.ImportSubjectPublicKeyInfo (.NET Core 3+ / PowerShell 7)
    # or the X509Certificates.PublicKey constructor (.NET Framework / Windows PowerShell 5.1).
    param([byte[]]$Bytes, [string]$Format, [byte[]]$Pkcs1)
    try {
        $hasImport = @([System.Security.Cryptography.RSA].GetMethods() | Where-Object { $_.Name -eq 'ImportSubjectPublicKeyInfo' }).Count -gt 0
        if ($hasImport) {
            $rsa = [System.Security.Cryptography.RSA]::Create()
            $read = 0
            if ($Format -eq 'SPKI') { $rsa.ImportSubjectPublicKeyInfo($Bytes, [ref]$read) } else { $rsa.ImportRSAPublicKey($Bytes, [ref]$read) }
            return [pscustomobject]@{ Bits = $rsa.KeySize; Method = 'RSA.ImportSubjectPublicKeyInfo' }
        }
        $oid = New-Object System.Security.Cryptography.Oid('1.2.840.113549.1.1.1')
        $params = New-Object System.Security.Cryptography.AsnEncodedData($oid, [byte[]](5, 0))
        $key = New-Object System.Security.Cryptography.AsnEncodedData($oid, $Pkcs1)
        $pk = New-Object System.Security.Cryptography.X509Certificates.PublicKey($oid, $params, $key)
        [pscustomobject]@{ Bits = $pk.Key.KeySize; Method = 'X509Certificates.PublicKey' }
    }
    catch {
        [pscustomobject]@{ Bits = $null; Method = 'unavailable'; Error = $_.Exception.Message }
    }
}

function Get-DkimKeyInfo {
    # Decodes the p= value of a DKIM key record. Key size comes from the DER structure, never from base64 length.
    param([string]$PublicKey, [string]$KeyType = 'rsa')
    $info = [ordered]@{ KeyType = $null; Bits = $null; Format = $null; Revoked = $false; PlatformBits = $null; PlatformMethod = $null; Error = $null }
    $clean = ([string]$PublicKey) -replace '\s', ''
    if (-not $clean) { $info.Revoked = $true; return [pscustomobject]$info }
    try { $bytes = [Convert]::FromBase64String($clean) }
    catch { $info.Error = 'p= is not valid base64'; return [pscustomobject]$info }
    if ($KeyType -and $KeyType.ToLowerInvariant() -eq 'ed25519') {
        $info.KeyType = 'Ed25519'; $info.Format = 'Raw'; $info.Bits = $bytes.Length * 8
        return [pscustomobject]$info
    }
    try {
        $m = Get-RsaModulusFromDer $bytes
        $info.KeyType = $m.Algorithm; $info.Format = $m.Format; $info.Bits = $m.Bits
        if ($m.Algorithm -eq 'RSA') {
            $p = Get-RsaKeySizePlatform -Bytes $bytes -Format $m.Format -Pkcs1 $m.Pkcs1
            $info.PlatformBits = $p.Bits; $info.PlatformMethod = $p.Method
            if ($p.Bits -and $p.Bits -ne $m.Bits) { Write-Verbose "DKIM key size mismatch: DER $($m.Bits) vs $($p.Method) $($p.Bits)" }
        }
    }
    catch { $info.Error = $_.Exception.Message }
    [pscustomobject]$info
}

function Get-DkimCnameClass {
    param([string]$Target)
    $t = ConvertTo-DnsName $Target
    if ($t -match '^selector\d+-[a-z0-9-]+\._domainkey\.[a-z0-9-]+\.onmicrosoft\.(com|us)$') { return 'EOP' }
    if ($t -match '\._domainkey\.[a-z0-9.-]+\.dkim\.mail\.microsoft$') { return 'EOP' }
    'Other'
}

function Get-DkimAssessment {
    param([string]$Domain, [hashtable]$Context, [string[]]$Selector)
    $findings = [System.Collections.Generic.List[object]]::new()
    $all = @(@('selector1', 'selector2') + @($Selector | Where-Object { $_ } | ForEach-Object { $_.Trim().ToLowerInvariant() }) | Select-Object -Unique)
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($sel in $all) {
        $name = "$sel._domainkey.$Domain"
        $c = Resolve-Record -Name $name -Type CNAME -Context $Context
        $t = Resolve-Record -Name $name -Type TXT -Context $Context
        $cname = @(Get-AnswerRecord $c 'CNAME' | Where-Object { $_.Name -eq $name })
        $txt = @(Get-AnswerRecord $t 'TXT')
        $isEop = $sel -in @('selector1', 'selector2')
        $o = [ordered]@{
            Selector = $sel; Name = $name; Status = $t.Status; Resolver = $t.Resolver; RecordType = 'None'; CnameTarget = $null; CnameClass = $null
            TTL = $null; Record = $null; Version = $null; KeyType = $null; Bits = $null; Revoked = $false; TestMode = $false; Error = $null
        }
        if ($cname.Count) {
            $o.RecordType = 'CNAME'; $o.CnameTarget = $cname[0].Target; $o.CnameClass = Get-DkimCnameClass $cname[0].Target; $o.TTL = $cname[0].TTL
            if ($isEop -and $o.CnameClass -ne 'EOP') { $findings.Add((New-Finding -RuleId 'DKIM-009' -Domain $Domain -Target $name -Message "$name points to $($o.CnameTarget)")) }
            if ($isEop -and $o.CnameClass -eq 'EOP' -and $o.CnameTarget -notlike "$sel-*") { $findings.Add((New-Finding -RuleId 'DKIM-015' -Domain $Domain -Target $name -Message "$name points to $($o.CnameTarget)")) }
            if ($txt.Count -eq 0 -and (Test-ResolvedStatus $t.Status)) { $findings.Add((New-Finding -RuleId 'DKIM-011' -Domain $Domain -Target $name -Message "$name -> $($o.CnameTarget) has no TXT key")) }
        }
        elseif ($txt.Count) {
            $o.RecordType = 'TXT'; $o.TTL = $txt[0].TTL
            if ($isEop) { $findings.Add((New-Finding -RuleId 'DKIM-004' -Domain $Domain -Target $name -Message "$name is a TXT record, not a CNAME to the tenant")) }
        }
        elseif ((Test-ResolvedStatus $t.Status) -and -not $isEop) {
            $findings.Add((New-Finding -RuleId 'DKIM-003' -Domain $Domain -Target $name -Message "No key at $name"))
        }
        if ($txt.Count -gt 1) { $findings.Add((New-Finding -RuleId 'DKIM-014' -Domain $Domain -Target $name -Message "$($txt.Count) TXT records at $name")) }
        if ($txt.Count) {
            $o.Record = $txt[0].Data
            $tags = (ConvertFrom-TagValueRecord $txt[0].Data).Tags
            $o.Version = $tags['v']
            if (-not $tags.Contains('p')) {
                $o.Error = 'No p= tag'
                $findings.Add((New-Finding -RuleId 'DKIM-008' -Domain $Domain -Target $name -Message "$name has no p= tag"))
            }
            else {
                $k = if ($tags.Contains('k')) { $tags['k'] } else { 'rsa' }
                $ki = Get-DkimKeyInfo -PublicKey $tags['p'] -KeyType $k
                $o.KeyType = $ki.KeyType; $o.Bits = $ki.Bits; $o.Revoked = $ki.Revoked; $o.Error = $ki.Error
                if ($ki.Revoked) { $findings.Add((New-Finding -RuleId 'DKIM-007' -Domain $Domain -Target $name)) }
                elseif ($ki.Error) { $findings.Add((New-Finding -RuleId 'DKIM-008' -Domain $Domain -Target $name -Message "$name : $($ki.Error)")) }
                elseif ($ki.KeyType -ne 'RSA') { $findings.Add((New-Finding -RuleId 'DKIM-010' -Domain $Domain -Target $name -Message "$name uses $($ki.KeyType)")) }
                elseif ($ki.Bits -lt 1024) { $findings.Add((New-Finding -RuleId 'DKIM-006' -Domain $Domain -Target $name -Message "$name RSA key is $($ki.Bits) bits")) }
                elseif ($ki.Bits -lt 2048) { $findings.Add((New-Finding -RuleId 'DKIM-005' -Domain $Domain -Target $name -Message "$name RSA key is $($ki.Bits) bits")) }
            }
            if ($tags.Contains('t') -and (@($tags['t'] -split ':' | ForEach-Object { $_.Trim() }) -contains 'y')) {
                $o.TestMode = $true
                $findings.Add((New-Finding -RuleId 'DKIM-012' -Domain $Domain -Target $name))
            }
            if ($tags.Contains('h') -and (@($tags['h'] -split ':' | ForEach-Object { $_.Trim().ToLowerInvariant() }) -notcontains 'sha256')) {
                $findings.Add((New-Finding -RuleId 'DKIM-013' -Domain $Domain -Target $name -Message "$name h=$($tags['h'])"))
            }
        }
        $results.Add([pscustomobject]$o)
    }
    $eop = @($results | Where-Object { $_.Selector -in @('selector1', 'selector2') })
    $present = @($eop | Where-Object { $_.RecordType -ne 'None' })
    $resolved = @($eop | Where-Object { Test-ResolvedStatus $_.Status }).Count -eq $eop.Count
    if ($resolved -and $present.Count -eq 0) { $findings.Add((New-Finding -RuleId 'DKIM-001' -Domain $Domain)) }
    elseif ($resolved -and $present.Count -eq 1) {
        $missing = @($eop | Where-Object { $_.RecordType -eq 'None' })[0].Selector
        $findings.Add((New-Finding -RuleId 'DKIM-002' -Domain $Domain -Message "$missing is not published"))
    }
    [pscustomobject]@{ Selectors = @($results); Findings = @($findings) }
}

#endregion

#region DMARC

function ConvertFrom-DmarcRecord {
    param([string]$Record)
    $parsed = ConvertFrom-TagValueRecord $Record
    $tags = $parsed.Tags
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($e in $parsed.Errors) { $errors.Add($e) }
    $keys = @($tags.Keys)
    if ($keys.Count -eq 0 -or $keys[0] -ne 'v' -or $tags['v'] -ne 'DMARC1') { $errors.Add('First tag must be v=DMARC1') }
    $policies = @('none', 'quarantine', 'reject')
    $p = if ($tags.Contains('p')) { $tags['p'].ToLowerInvariant() } else { $null }
    if (-not $p) { $errors.Add('Missing p= tag') } elseif ($p -notin $policies) { $errors.Add("Invalid p=$p") }
    $sp = if ($tags.Contains('sp')) { $tags['sp'].ToLowerInvariant() } else { $null }
    if ($sp -and $sp -notin $policies) { $errors.Add("Invalid sp=$sp") }
    $np = if ($tags.Contains('np')) { $tags['np'].ToLowerInvariant() } else { $null }
    $pct = 100
    if ($tags.Contains('pct')) {
        if ($tags['pct'] -match '^\d{1,3}$' -and [int]$tags['pct'] -le 100) { $pct = [int]$tags['pct'] } else { $errors.Add("Invalid pct=$($tags['pct'])") }
    }
    foreach ($a in @('adkim', 'aspf')) { if ($tags.Contains($a) -and $tags[$a] -notin @('r', 's')) { $errors.Add("Invalid $a=$($tags[$a])") } }
    $uris = @{}
    foreach ($kind in @('rua', 'ruf')) {
        $list = [System.Collections.Generic.List[object]]::new()
        if ($tags.Contains($kind)) {
            foreach ($u in ($tags[$kind] -split ',')) {
                $u = $u.Trim()
                if (-not $u) { continue }
                if ($u -match '^mailto:(?<addr>[^@!\s]+@(?<dom>[^!\s]+))(?<size>!\d+[kmgt]?)?$') {
                    $list.Add([pscustomobject]@{ Uri = $u; Address = $Matches['addr']; Domain = ConvertTo-DnsName $Matches['dom'] })
                }
                else { $errors.Add("Invalid $kind URI '$u'") }
            }
        }
        $uris[$kind] = @($list)
    }
    [pscustomobject]@{
        Valid = ($errors.Count -eq 0); Errors = @($errors); Tags = $tags
        P = $p; Sp = $sp; Np = $np; Pct = $pct; Rua = $uris['rua']; Ruf = $uris['ruf']
        Adkim = $(if ($tags.Contains('adkim')) { $tags['adkim'] } else { 'r' }); Aspf = $(if ($tags.Contains('aspf')) { $tags['aspf'] } else { 'r' })
        Fo = $tags['fo']; Rf = $tags['rf']; Ri = $tags['ri']
    }
}

function Test-SameOrganization {
    # Approximation without a public suffix list: same name or one is a subdomain of the other.
    param([string]$A, [string]$B)
    (Test-InDomain $A $B) -or (Test-InDomain $B $A)
}

function Get-DmarcAssessment {
    param([string]$Domain, [hashtable]$Context, [string[]]$ScopeDomain)
    $findings = [System.Collections.Generic.List[object]]::new()
    $name = "_dmarc.$Domain"
    $r = Resolve-Record -Name $name -Type TXT -Context $Context
    $records = @(Get-AnswerRecord $r 'TXT' | Where-Object { $_.Data -match '^\s*v\s*=\s*DMARC1' } | ForEach-Object { $_.Data.Trim() })
    $out = [ordered]@{ Status = $r.Status; Resolver = $r.Resolver; TTL = $null; Record = $null; Parsed = $null; InheritedFrom = $null; ReportAuthorization = @(); Findings = $null }
    if (-not (Test-ResolvedStatus $r.Status)) { $out.Findings = @(); return [pscustomobject]$out }
    if ($records.Count -eq 0) {
        $labels = $Domain -split '\.'
        for ($i = 1; $i -le $labels.Count - 2; $i++) {
            $parent = ($labels[$i..($labels.Count - 1)]) -join '.'
            $pr = Resolve-Record -Name "_dmarc.$parent" -Type TXT -Context $Context
            $pRec = @(Get-AnswerRecord $pr 'TXT' | Where-Object { $_.Data -match '^\s*v\s*=\s*DMARC1' })
            if ($pRec.Count) { $out.InheritedFrom = $parent; $out.Record = $pRec[0].Data; break }
        }
        if ($out.InheritedFrom) {
            $pp = ConvertFrom-DmarcRecord $out.Record
            $eff = if ($pp.Sp) { $pp.Sp } else { $pp.P }
            $findings.Add((New-Finding -RuleId 'DMARC-012' -Domain $Domain -Message "No record at $name; policy of $($out.InheritedFrom) applies (effective $eff)"))
        }
        else { $findings.Add((New-Finding -RuleId 'DMARC-001' -Domain $Domain)) }
        $out.Findings = @($findings)
        return [pscustomobject]$out
    }
    if ($records.Count -gt 1) { $findings.Add((New-Finding -RuleId 'DMARC-002' -Domain $Domain -Message "$($records.Count) DMARC records at $name")) }
    $out.Record = $records[0]
    $out.TTL = @(Get-AnswerRecord $r 'TXT')[0].TTL
    $d = ConvertFrom-DmarcRecord $records[0]
    $out.Parsed = $d
    if (-not $d.Valid) { $findings.Add((New-Finding -RuleId 'DMARC-009' -Domain $Domain -Message ($d.Errors -join '; '))) }
    if ($d.P -eq 'none') { $findings.Add((New-Finding -RuleId 'DMARC-003' -Domain $Domain)) }
    if ($d.Pct -lt 100) { $findings.Add((New-Finding -RuleId 'DMARC-004' -Domain $Domain -Message "pct=$($d.Pct)")) }
    $subs = @($ScopeDomain | Where-Object { $_ -ne $Domain -and (Test-InDomain $_ $Domain) })
    if (-not $d.Sp -and $subs.Count) { $findings.Add((New-Finding -RuleId 'DMARC-005' -Domain $Domain -Message ('sp not set; subdomains in scope: ' + ($subs -join ', ')))) }
    if ($d.Sp -eq 'none' -and $d.P -in @('quarantine', 'reject')) { $findings.Add((New-Finding -RuleId 'DMARC-011' -Domain $Domain -Message "p=$($d.P) but sp=none")) }
    if ($d.Rua.Count -eq 0) { $findings.Add((New-Finding -RuleId 'DMARC-006' -Domain $Domain)) }
    if ($d.Ruf.Count -gt 0) { $findings.Add((New-Finding -RuleId 'DMARC-008' -Domain $Domain)) }
    if ($d.Adkim -eq 's' -or $d.Aspf -eq 's') { $findings.Add((New-Finding -RuleId 'DMARC-010' -Domain $Domain -Message "adkim=$($d.Adkim) aspf=$($d.Aspf)")) }
    $auth = [System.Collections.Generic.List[object]]::new()
    foreach ($dest in @(@($d.Rua) + @($d.Ruf) | ForEach-Object { $_.Domain } | Select-Object -Unique)) {
        if (Test-SameOrganization $dest $Domain) { continue }
        $q = Resolve-Record -Name "$Domain._report._dmarc.$dest" -Type TXT -Context $Context
        $ok = @(Get-AnswerRecord $q 'TXT' | Where-Object { $_.Data -match '^\s*v\s*=\s*DMARC1' }).Count -gt 0
        $auth.Add([pscustomobject]@{ Destination = $dest; Record = "$Domain._report._dmarc.$dest"; Status = $q.Status; Authorized = $ok })
        if (-not $ok -and (Test-ResolvedStatus $q.Status)) {
            $findings.Add((New-Finding -RuleId 'DMARC-007' -Domain $Domain -Target $dest -Message "$dest does not publish $Domain._report._dmarc.$dest"))
        }
    }
    $out.ReportAuthorization = @($auth)
    $out.Findings = @($findings)
    [pscustomobject]$out
}

#endregion

#region MTA-STS and TLS-RPT

function ConvertFrom-MtaStsPolicy {
    param([string]$Text)
    $o = [ordered]@{ Version = $null; Mode = $null; MaxAge = $null; Mx = @(); Errors = @() }
    $mx = [System.Collections.Generic.List[string]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($Text -split "`r?`n")) {
        $l = $line.Trim()
        if (-not $l) { continue }
        if ($l -notmatch '^(?<k>[A-Za-z0-9_]+)\s*:\s*(?<v>.*)$') { $errors.Add("Invalid line '$l'"); continue }
        $v = $Matches['v'].Trim()
        switch ($Matches['k'].ToLowerInvariant()) {
            'version' { $o.Version = $v }
            'mode' { $o.Mode = $v.ToLowerInvariant() }
            'max_age' { if ($v -match '^\d{1,10}$') { $o.MaxAge = [int64]$v } else { $errors.Add("Invalid max_age '$v'") } }
            'mx' { $mx.Add($v.ToLowerInvariant()) }
        }
    }
    if ($o.Version -ne 'STSv1') { $errors.Add('version must be STSv1') }
    if ($o.Mode -notin @('enforce', 'testing', 'none')) { $errors.Add("Invalid mode '$($o.Mode)'") }
    if ($null -eq $o.MaxAge) { $errors.Add('max_age missing') } elseif ($o.MaxAge -gt 31557600) { $errors.Add('max_age above 31557600') }
    if ($mx.Count -eq 0 -and $o.Mode -ne 'none') { $errors.Add('No mx lines') }
    $o.Mx = @($mx)
    $o.Errors = @($errors)
    [pscustomobject]$o
}

function Get-MtaStsPolicy {
    param([string]$Domain, [int]$TimeoutSeconds)
    $o = [ordered]@{ Url = "https://mta-sts.$Domain/.well-known/mta-sts.txt"; StatusCode = $null; ContentType = $null; Content = $null; Error = $null }
    try {
        $resp = Invoke-WebRequest -Uri $o.Url -UseBasicParsing -MaximumRedirection 0 -TimeoutSec ([Math]::Max(10, $TimeoutSeconds * 2)) -ErrorAction Stop
        $o.StatusCode = [int]$resp.StatusCode
        $o.ContentType = [string](@($resp.Headers['Content-Type'])[0])
        $content = $resp.Content
        if ($content -is [byte[]]) { $content = [System.Text.Encoding]::UTF8.GetString($content) }
        $o.Content = [string]$content
    }
    catch {
        $o.Error = $_.Exception.Message
        $response = $_.Exception.Response
        if ($response) { try { $o.StatusCode = [int]$response.StatusCode } catch { $o.StatusCode = $null } }
    }
    [pscustomobject]$o
}

function Get-TlsCertificateInfo {
    # Direct TLS handshake to read the certificate (subject, SAN, expiry, chain). Does not use a proxy.
    param([string]$HostName, [int]$Port = 443, [int]$TimeoutSeconds = 5)
    $o = [ordered]@{ Host = $HostName; Retrieved = $false; Subject = $null; Issuer = $null; NotBefore = $null; NotAfter = $null; DaysRemaining = $null; DnsNames = @(); NameMatch = $null; PolicyErrors = $null; Valid = $null; Error = $null }
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $tcp.BeginConnect($HostName, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($TimeoutSeconds * 1000)) { throw 'TCP connect timed out' }
        $tcp.EndConnect($ar)
        $tcp.ReceiveTimeout = $TimeoutSeconds * 1000
        $tcp.SendTimeout = $TimeoutSeconds * 1000
        $box = @{ Errors = $null }
        $callback = [System.Net.Security.RemoteCertificateValidationCallback] { param($s, $c, $ch, $e) $box.Errors = $e; $true }.GetNewClosure()
        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)
        try {
            $protocols = [System.Security.Authentication.SslProtocols]::Tls12
            if ($PSVersionTable.PSEdition -eq 'Core' -and [enum]::GetNames([System.Security.Authentication.SslProtocols]) -contains 'Tls13') {
                $protocols = $protocols -bor [System.Security.Authentication.SslProtocols]::Tls13
            }
            $ssl.AuthenticateAsClient($HostName, $null, $protocols, $false)
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
            $o.Retrieved = $true
            $o.Subject = $cert.Subject
            $o.Issuer = $cert.Issuer
            $o.NotBefore = $cert.NotBefore.ToUniversalTime().ToString('o')
            $o.NotAfter = $cert.NotAfter.ToUniversalTime().ToString('o')
            $o.DaysRemaining = [int][Math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
            $san = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
            if ($san) { $o.DnsNames = @([regex]::Matches($san.Format($false), '(?:DNS Name|DNS)[=:]\s*([^,\s]+)') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() }) }
            $o.NameMatch = @($o.DnsNames | Where-Object { Test-HostPattern $_ $HostName }).Count -gt 0
            $o.PolicyErrors = [string]$box.Errors
            $o.Valid = ($box.Errors -eq [System.Net.Security.SslPolicyErrors]::None) -and $o.NameMatch -and $o.DaysRemaining -ge 0
        }
        finally { $ssl.Dispose() }
    }
    catch { $o.Error = $_.Exception.GetBaseException().Message }
    finally { $tcp.Close() }
    [pscustomobject]$o
}

function Get-MtaStsAssessment {
    param([string]$Domain, [hashtable]$Context, [object]$Mx)
    $findings = [System.Collections.Generic.List[object]]::new()
    $t = Resolve-Record -Name "_mta-sts.$Domain" -Type TXT -Context $Context
    $txt = @(Get-AnswerRecord $t 'TXT' | Where-Object { $_.Data -match '^\s*v=STSv1' })
    $o = [ordered]@{ TxtStatus = $t.Status; TxtRecord = $null; Id = $null; Policy = $null; Fetch = $null; Certificate = $null; Mode = 'None'; UncoveredMx = @(); TlsRpt = $null; Findings = $null }
    if ($txt.Count) {
        $o.TxtRecord = $txt[0].Data
        $tags = (ConvertFrom-TagValueRecord $txt[0].Data).Tags
        $o.Id = $tags['id']
        if ($txt.Count -gt 1 -or -not $tags['id'] -or $tags['id'] -notmatch '^[A-Za-z0-9]{1,32}$') {
            $findings.Add((New-Finding -RuleId 'MTASTS-010' -Domain $Domain -Message "_mta-sts.$Domain : $($txt[0].Data)"))
        }
    }
    # The policy is fetched once per run (HTTPS does not depend on the DNS vantage).
    $cacheKey = "mtasts|$Domain"
    if (-not $Context.Cache.ContainsKey($cacheKey)) {
        $fetch = Get-MtaStsPolicy -Domain $Domain -TimeoutSeconds $Context.TimeoutSeconds
        $cert = $null
        if ($fetch.StatusCode -or $txt.Count) { $cert = Get-TlsCertificateInfo -HostName "mta-sts.$Domain" -TimeoutSeconds $Context.TimeoutSeconds }
        $Context.Cache[$cacheKey] = @($fetch, $cert)
    }
    $fetch = $Context.Cache[$cacheKey][0]
    $cert = $Context.Cache[$cacheKey][1]
    $o.Fetch = [pscustomobject]@{ Url = $fetch.Url; StatusCode = $fetch.StatusCode; ContentType = $fetch.ContentType; Error = $fetch.Error }
    $o.Certificate = $cert
    $hasPolicy = ($fetch.StatusCode -eq 200 -and $fetch.Content)
    if (-not $txt.Count -and -not $hasPolicy) { $findings.Add((New-Finding -RuleId 'MTASTS-001' -Domain $Domain)) }
    elseif ($txt.Count -and -not $hasPolicy) {
        $why = if ($fetch.StatusCode) { "HTTP $($fetch.StatusCode)" } else { $fetch.Error }
        $findings.Add((New-Finding -RuleId 'MTASTS-002' -Domain $Domain -Message "Policy fetch failed: $why"))
    }
    elseif (-not $txt.Count -and $hasPolicy) { $findings.Add((New-Finding -RuleId 'MTASTS-003' -Domain $Domain)) }
    if ($cert -and $cert.Retrieved) {
        if (-not $cert.Valid) { $findings.Add((New-Finding -RuleId 'MTASTS-008' -Domain $Domain -Message "Certificate for mta-sts.$Domain : name match $($cert.NameMatch), policy errors $($cert.PolicyErrors), days remaining $($cert.DaysRemaining)")) }
        elseif ($cert.DaysRemaining -lt 30) { $findings.Add((New-Finding -RuleId 'MTASTS-012' -Domain $Domain -Message "Certificate expires in $($cert.DaysRemaining) days")) }
    }
    if ($hasPolicy) {
        $p = ConvertFrom-MtaStsPolicy $fetch.Content
        $o.Policy = $p
        $o.Mode = if ($p.Mode) { $p.Mode } else { 'Invalid' }
        if ($fetch.ContentType -and $fetch.ContentType -notmatch '^text/plain') { $findings.Add((New-Finding -RuleId 'MTASTS-013' -Domain $Domain -Message "Content-Type $($fetch.ContentType)")) }
        if ($p.Errors.Count) { $findings.Add((New-Finding -RuleId 'MTASTS-009' -Domain $Domain -Message ($p.Errors -join '; '))) }
        if ($p.Mode -in @('none', 'testing')) { $findings.Add((New-Finding -RuleId 'MTASTS-006' -Domain $Domain -Message "mode: $($p.Mode)")) }
        if ($null -ne $p.MaxAge -and $p.MaxAge -lt 86400) { $findings.Add((New-Finding -RuleId 'MTASTS-007' -Domain $Domain -Message "max_age: $($p.MaxAge)")) }
        $hosts = @($Mx.Hosts | ForEach-Object { $_.Host })
        $uncovered = @($hosts | Where-Object { $h = $_; @($p.Mx | Where-Object { Test-HostPattern $_ $h }).Count -eq 0 })
        $o.UncoveredMx = $uncovered
        if ($uncovered.Count -and $p.Mode -eq 'enforce') { $findings.Add((New-Finding -RuleId 'MTASTS-004' -Domain $Domain -Message ('Not in policy: ' + ($uncovered -join ', ')))) }
        elseif ($uncovered.Count -and $p.Mode -eq 'testing') { $findings.Add((New-Finding -RuleId 'MTASTS-005' -Domain $Domain -Message ('Not in policy: ' + ($uncovered -join ', ')))) }
        $eopAllowed = @($p.Mx | Where-Object { (Test-HostPattern $_ 'tenant-com.mail.protection.outlook.com') -or $_ -like '*.mx.microsoft' }).Count -gt 0
        $mxOnEop = @($Mx.Hosts | Where-Object { $_.Class -like 'EOP*' }).Count -gt 0
        if ($p.Mode -eq 'enforce' -and -not $eopAllowed -and -not $mxOnEop) { $findings.Add((New-Finding -RuleId 'MTASTS-011' -Domain $Domain)) }
    }
    $rpt = Resolve-Record -Name "_smtp._tls.$Domain" -Type TXT -Context $Context
    $rptTxt = @(Get-AnswerRecord $rpt 'TXT' | Where-Object { $_.Data -match '^\s*v=TLSRPTv1' })
    $o.TlsRpt = [pscustomobject]@{ Status = $rpt.Status; Record = $(if ($rptTxt.Count) { $rptTxt[0].Data } else { $null }); Rua = $null }
    if (Test-ResolvedStatus $rpt.Status) {
        if ($rptTxt.Count -eq 0) { $findings.Add((New-Finding -RuleId 'TLSRPT-001' -Domain $Domain)) }
        else {
            $o.TlsRpt.Rua = (ConvertFrom-TagValueRecord $rptTxt[0].Data).Tags['rua']
            if ($rptTxt.Count -gt 1 -or -not $o.TlsRpt.Rua) { $findings.Add((New-Finding -RuleId 'TLSRPT-002' -Domain $Domain -Message $rptTxt[0].Data)) }
        }
    }
    $o.Findings = @($findings)
    [pscustomobject]$o
}

#endregion

#region DANE and DNSSEC

function Get-DaneAssessment {
    param([string]$Domain, [hashtable]$Context, [object]$Mx)
    $findings = [System.Collections.Generic.List[object]]::new()
    $hosts = [System.Collections.Generic.List[object]]::new()
    foreach ($h in @($Mx.Hosts | ForEach-Object { $_.Host } | Select-Object -Unique)) {
        $name = "_25._tcp.$h"
        $r = Resolve-Record -Name $name -Type TLSA -Context $Context -DnssecOk
        $tlsa = @(Get-AnswerRecord $r 'TLSA' | ForEach-Object {
                $p = $_.Data -split ' '
                [pscustomobject]@{ Usage = [int]$p[0]; Selector = [int]$p[1]; MatchingType = [int]$p[2]; Data = $p[3]; TTL = $_.TTL }
            })
        $hosts.Add([pscustomobject]@{ Host = $h; Name = $name; Status = $r.Status; Resolver = $r.Resolver; Signed = $r.Signed; Validated = $r.Authenticated; Records = $tlsa })
        if ($r.Status -eq 'ServFail') { $findings.Add((New-Finding -RuleId 'DANE-005' -Domain $Domain -Target $name)) }
        elseif ($tlsa.Count -eq 0) { if (Test-ResolvedStatus $r.Status) { $findings.Add((New-Finding -RuleId 'DANE-003' -Domain $Domain -Target $name)) } }
        else {
            if (-not $r.Signed -and -not $r.Authenticated) { $findings.Add((New-Finding -RuleId 'DANE-001' -Domain $Domain -Target $name)) }
            elseif (-not $r.Authenticated) { $findings.Add((New-Finding -RuleId 'DANE-002' -Domain $Domain -Target $name)) }
            if (@($tlsa | Where-Object { $_.Usage -lt 2 }).Count) { $findings.Add((New-Finding -RuleId 'DANE-004' -Domain $Domain -Target $name)) }
        }
    }
    $withTlsa = @($hosts | Where-Object { $_.Records.Count })
    $state = if ($hosts.Count -eq 0 -or $withTlsa.Count -eq 0) { 'None' }
    elseif (@($withTlsa | Where-Object { $_.Validated }).Count -eq $hosts.Count) { 'Validated' }
    elseif ($withTlsa.Count -lt $hosts.Count) { 'Partial' }
    else { 'Unvalidated' }
    [pscustomobject]@{ State = $state; Hosts = @($hosts); Findings = @($findings) }
}

function Get-DnssecAssessment {
    param([string]$Domain, [hashtable]$Context)
    $findings = [System.Collections.Generic.List[object]]::new()
    $queries = [System.Collections.Generic.List[object]]::new()
    $bogus = $false
    foreach ($type in @('SOA', 'MX')) {
        $r = Resolve-Record -Name $Domain -Type $type -Context $Context -DnssecOk
        $cd = $null
        if ($r.Status -eq 'ServFail') {
            $cd = Resolve-Record -Name $Domain -Type $type -Context $Context -DnssecOk -CheckingDisabled
            if (Test-ResolvedStatus $cd.Status) { $bogus = $true }
        }
        $queries.Add([pscustomobject]@{ Type = $type; Status = $r.Status; Resolver = $r.Resolver; AD = $r.Authenticated; Signed = $r.Signed; StatusWithCD = $(if ($cd) { $cd.Status } else { $null }) })
    }
    $soa = $queries[0]
    $state = if ($bogus) { 'Bogus' }
    elseif (-not (Test-ResolvedStatus $soa.Status)) { 'Unknown' }
    elseif ($soa.AD) { 'Validated' }
    elseif ($soa.Signed) { 'SignedNotValidated' }
    else { 'Unsigned' }
    switch ($state) {
        'Bogus' { $findings.Add((New-Finding -RuleId 'DNSSEC-003' -Domain $Domain -Message 'SERVFAIL with DNSSEC validation, answer with checking disabled')) }
        'SignedNotValidated' { $findings.Add((New-Finding -RuleId 'DNSSEC-002' -Domain $Domain -Message "RRSIG present, AD not set by $($soa.Resolver)")) }
        'Unsigned' { $findings.Add((New-Finding -RuleId 'DNSSEC-001' -Domain $Domain)) }
    }
    [pscustomobject]@{ State = $state; Queries = @($queries); Findings = @($findings) }
}

#endregion

#region Other records

function Get-TxtClassification {
    param([string]$Text)
    $t = $Text.Trim()
    if ($t -match '^v=spf1(\s|$)') { return 'SPF' }
    if ($t -match '^v\s*=\s*DMARC1') { return 'DMARC (misplaced)' }
    if ($t -match '^v=DKIM1|^k=rsa;\s*p=') { return 'DKIM (misplaced)' }
    if ($t -match '^v=STSv1') { return 'MTA-STS (misplaced)' }
    if ($t -match '^MS=ms\d+') { return 'Microsoft 365 verification' }
    if ($t -match '^google-site-verification=') { return 'Google verification' }
    if ($t -match '(?i)^[a-z0-9._-]*(verif|validat|ownership|domain-key|site-key)[a-z0-9._-]*[=:]' -or $t -match '(?i)^docusign=') { return 'Verification token' }
    'Other'
}

function Get-OtherRecords {
    param([string]$Domain, [hashtable]$Context, [string[]]$ScopeDomain)
    $findings = [System.Collections.Generic.List[object]]::new()
    # Autodiscover
    $ac = Resolve-Record -Name "autodiscover.$Domain" -Type CNAME -Context $Context
    $acTarget = @(Get-AnswerRecord $ac 'CNAME' | Where-Object { $_.Name -eq "autodiscover.$Domain" } | ForEach-Object { $_.Target })
    $aa = $null
    if (-not $acTarget.Count) { $aa = Resolve-Record -Name "autodiscover.$Domain" -Type A -Context $Context }
    $srv = Resolve-Record -Name "_autodiscover._tcp.$Domain" -Type SRV -Context $Context
    $srvTargets = @(Get-AnswerRecord $srv 'SRV' | ForEach-Object { $_.Target })
    $classify = {
        param($target)
        if ($target -match '(^|\.)outlook\.com$') { 'Microsoft365' }
        elseif (@($ScopeDomain | Where-Object { Test-InDomain $target $_ }).Count) { 'OnPremises' }
        else { 'Other' }
    }
    $adClass = 'None'
    $adTarget = $null
    if ($acTarget.Count) { $adTarget = $acTarget[0]; $adClass = & $classify $adTarget }
    elseif ($aa -and @(Get-AnswerRecord $aa 'A').Count) { $adTarget = (@(Get-AnswerRecord $aa 'A') | ForEach-Object { $_.Data }) -join ', '; $adClass = 'OnPremises' }
    elseif ($srvTargets.Count) { $adTarget = $srvTargets[0]; $adClass = & $classify $adTarget }
    $resolvedAd = (Test-ResolvedStatus $ac.Status) -and (Test-ResolvedStatus $srv.Status)
    if ($adClass -eq 'None' -and $resolvedAd) { $findings.Add((New-Finding -RuleId 'AUTOD-001' -Domain $Domain)) }
    elseif ($adClass -in @('OnPremises', 'Other')) { $findings.Add((New-Finding -RuleId 'AUTOD-002' -Domain $Domain -Message "Autodiscover points to $adTarget ($adClass)")) }

    # Teams/Skype and device registration: reported only if present.
    $optional = @(
        @("_sip._tls.$Domain", 'SRV', 'Teams/Skype'), @("_sipfederationtls._tcp.$Domain", 'SRV', 'Teams/Skype'), @("lyncdiscover.$Domain", 'CNAME', 'Teams/Skype'),
        @("enterpriseregistration.$Domain", 'CNAME', 'Entra'), @("enterpriseenrollment.$Domain", 'CNAME', 'Intune'), @("msoid.$Domain", 'CNAME', 'Legacy')
    )
    $present = [System.Collections.Generic.List[object]]::new()
    foreach ($q in $optional) {
        $r = Resolve-Record -Name $q[0] -Type $q[1] -Context $Context
        foreach ($rec in @(Get-AnswerRecord $r $q[1] | Where-Object { $_.Name -eq $q[0] })) {
            $present.Add([pscustomobject]@{ Name = $q[0]; Type = $q[1]; Purpose = $q[2]; Target = $rec.Target; TTL = $rec.TTL; Microsoft = ($rec.Target -match '(lync\.com|microsoft\.com|windows\.net|microsoftonline(-p)?\.(com|net))$') })
        }
    }
    if (@($present | Where-Object { $_.Purpose -eq 'Legacy' }).Count) { $findings.Add((New-Finding -RuleId 'OTHER-001' -Domain $Domain -Target "msoid.$Domain")) }
    $info = @($present | Where-Object { $_.Purpose -ne 'Legacy' })
    if ($info.Count) { $findings.Add((New-Finding -RuleId 'OTHER-002' -Domain $Domain -Message ('Present: ' + (($info | ForEach-Object { "$($_.Name) -> $($_.Target)" }) -join '; ')))) }

    # Apex TXT inventory
    $txt = Resolve-Record -Name $Domain -Type TXT -Context $Context
    $inventory = @(Get-AnswerRecord $txt 'TXT' | ForEach-Object { [pscustomobject]@{ Class = Get-TxtClassification $_.Data; TTL = $_.TTL; Text = $_.Data } })
    $tokens = @($inventory | Where-Object { $_.Class -match 'verification|Verification token' })
    if ($tokens.Count) { $findings.Add((New-Finding -RuleId 'TXT-001' -Domain $Domain -Message ("$($tokens.Count) verification token(s): " + (($tokens | Group-Object Class | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join ', ')))) }
    if (@($inventory | Where-Object { $_.Class -eq 'Microsoft 365 verification' }).Count -gt 1) { $findings.Add((New-Finding -RuleId 'TXT-002' -Domain $Domain)) }
    if (@($inventory | Where-Object { $_.Class -eq 'DMARC (misplaced)' }).Count) { $findings.Add((New-Finding -RuleId 'DMARC-013' -Domain $Domain)) }

    $soa = Resolve-Record -Name $Domain -Type SOA -Context $Context
    $ns = Resolve-Record -Name $Domain -Type NS -Context $Context
    [pscustomobject]@{
        Autodiscover = [pscustomobject]@{ Class = $adClass; Target = $adTarget; Cname = $(if ($acTarget.Count) { $acTarget[0] } else { $null }); Srv = $srvTargets }
        Optional     = @($present)
        ApexTxt      = $inventory
        Soa          = @(Get-AnswerRecord $soa 'SOA' | ForEach-Object { $_.Data })
        NameServers  = @(Get-AnswerRecord $ns 'NS' | ForEach-Object { $_.Target })
        Findings     = @($findings)
    }
}

#endregion

#region Cross-vantage comparison

function Compare-Vantage {
    # Compares every name/type queried on both vantages (data compared without TTL).
    param([object[]]$Query)
    $groups = [ordered]@{}
    foreach ($q in $Query) {
        if ($q.CheckingDisabled) { continue }
        $key = "$($q.Name)|$($q.Type)"
        if (-not $groups.Contains($key)) { $groups[$key] = @{} }
        $slot = $groups[$key]
        if (-not $slot.ContainsKey($q.Vantage) -or ($slot[$q.Vantage].DnssecOk -and -not $q.DnssecOk)) { $slot[$q.Vantage] = $q }
    }
    $rows = foreach ($key in $groups.Keys) {
        $slot = $groups[$key]
        if (-not ($slot.ContainsKey('Internal') -and $slot.ContainsKey('External'))) { continue }
        $i = $slot['Internal']; $e = $slot['External']
        $iData = @($i.Records | ForEach-Object { "$($_.Type) $($_.Data)" } | Sort-Object -Unique)
        $eData = @($e.Records | ForEach-Object { "$($_.Type) $($_.Data)" } | Sort-Object -Unique)
        $iOk = Test-ResolvedStatus $i.Status
        $eOk = Test-ResolvedStatus $e.Status
        $result = if (-not $iOk -and -not $eOk) { 'FailedBoth' }
        elseif (-not $iOk) { 'FailedInternal' }
        elseif (-not $eOk) { 'FailedExternal' }
        elseif ($iData.Count -eq 0 -and $eData.Count -eq 0) { 'Identical' }
        elseif ($iData.Count -eq 0) { 'MissingInternal' }
        elseif ($eData.Count -eq 0) { 'MissingExternal' }
        elseif (($iData -join "`n") -ceq ($eData -join "`n")) { 'Identical' }
        else { 'Differs' }
        [pscustomobject]@{
            Name = $i.Name; Type = $i.Type; Result = $result
            InternalStatus = $i.Status; ExternalStatus = $e.Status
            InternalData = ($iData -join '; '); ExternalData = ($eData -join '; ')
            InternalTTL = (@($i.Records | ForEach-Object { $_.TTL }) -join ','); ExternalTTL = (@($e.Records | ForEach-Object { $_.TTL }) -join ',')
            InternalResolver = $i.Resolver; ExternalResolver = $e.Resolver
        }
    }
    @($rows)
}

function Get-VantageFinding {
    param([string]$Domain, [object[]]$Diff)
    foreach ($d in $Diff) {
        $target = "$($d.Name) $($d.Type)"
        $msg = "$target : internal [$($d.InternalStatus)] $($d.InternalData) / external [$($d.ExternalStatus)] $($d.ExternalData)"
        switch ($d.Result) {
            'Differs' {
                $rule = if ($d.Type -in @('A', 'AAAA')) { 'VANTAGE-004' } elseif ($d.Type -in @('SOA', 'NS')) { 'VANTAGE-005' } else { 'VANTAGE-001' }
                New-Finding -RuleId $rule -Domain $Domain -Target $target -Message $msg
            }
            { $_ -in @('MissingInternal', 'MissingExternal') } { New-Finding -RuleId 'VANTAGE-002' -Domain $Domain -Target $target -Message $msg }
            { $_ -in @('FailedInternal', 'FailedExternal') } { New-Finding -RuleId 'VANTAGE-003' -Domain $Domain -Target $target -Message $msg }
        }
    }
}

#endregion

#region Orchestration

function Get-DomainSummary {
    param([string]$Domain, $Checks, [object[]]$Finding)
    $pv = if ($Checks.Contains('External')) { 'External' } else { 'Internal' }
    $v = $Checks[$pv]
    $dkimCell = {
        param($sel)
        $s = @($v.Dkim.Selectors | Where-Object { $_.Selector -eq $sel })
        if (-not $s.Count -or $s[0].RecordType -eq 'None') { 'missing' }
        elseif ($s[0].Revoked) { 'revoked' }
        elseif ($s[0].Bits) { [string]$s[0].Bits }
        elseif ($s[0].RecordType -eq 'CNAME') { 'CNAME (no key)' }
        else { 'invalid' }
    }
    $o = [ordered]@{ Domain = $Domain; Vantage = $pv; Exists = $v.Exists }
    if ($v.Exists) {
        $o.MxClass = $v.Mx.Class
        $o.MxHosts = (@($v.Mx.Hosts | ForEach-Object { $_.Host }) -join ' ')
        $o.MxTTL = $v.Mx.TTL
        $o.SpfLookups = $v.Spf.Lookups
        $o.SpfVoidLookups = $v.Spf.VoidLookups
        $o.SpfAll = $(if ($v.Spf.Record) { if ($v.Spf.All) { "$($v.Spf.All)all" } else { 'missing' } } else { 'no record' })
        $o.SpfEop = $v.Spf.IncludesEop
        $o.DkimSelector1 = & $dkimCell 'selector1'
        $o.DkimSelector2 = & $dkimCell 'selector2'
        $dp = $v.Dmarc.Parsed
        $o.DmarcP = $(if ($dp) { $dp.P } elseif ($v.Dmarc.InheritedFrom) { 'inherited' } else { 'missing' })
        $o.DmarcSp = $(if ($dp) { $dp.Sp } else { $null })
        $o.DmarcPct = $(if ($dp) { $dp.Pct } else { $null })
        $o.MtaSts = $(if ($v.MtaSts) { $v.MtaSts.Mode } else { 'n/a' })
        $o.Dane = $(if ($v.Dane) { $v.Dane.State } else { 'n/a' })
        $o.Dnssec = $(if ($v.Dnssec) { $v.Dnssec.State } else { 'n/a' })
        $o.Autodiscover = $v.Other.Autodiscover.Class
    }
    foreach ($s in @('Critical', 'High', 'Medium', 'Info')) { $o[$s] = @($Finding | Where-Object { $_.Severity -eq $s }).Count }
    [pscustomobject]$o
}

function Invoke-DomainAssessment {
    param([string]$Domain, [hashtable[]]$Context, [hashtable]$Options)
    $allFindings = [System.Collections.Generic.List[object]]::new()
    $log = [System.Collections.Generic.List[object]]::new()
    $checks = [ordered]@{}
    foreach ($ctx in $Context) {
        $ctx.Log = [System.Collections.Generic.List[object]]::new()
        $v = [ordered]@{ Exists = $true; Mx = $null; Spf = $null; Dkim = $null; Dmarc = $null; MtaSts = $null; Dane = $null; Dnssec = $null; Other = $null }
        $found = [System.Collections.Generic.List[object]]::new()
        $soa = Resolve-Record -Name $Domain -Type SOA -Context $ctx
        if ($soa.Status -eq 'NXDomain') {
            $v.Exists = $false
            $found.Add((New-Finding -RuleId 'DOMAIN-001' -Domain $Domain))
        }
        else {
            $v.Mx = Get-MxAssessment -Domain $Domain -Context $ctx -ScopeDomain $Options.ScopeDomain
            $v.Spf = Get-SpfAssessment -Domain $Domain -Context $ctx
            $v.Dkim = Get-DkimAssessment -Domain $Domain -Context $ctx -Selector $Options.DkimSelector
            $v.Dmarc = Get-DmarcAssessment -Domain $Domain -Context $ctx -ScopeDomain $Options.ScopeDomain
            if ($Options.CheckMtaSts) { $v.MtaSts = Get-MtaStsAssessment -Domain $Domain -Context $ctx -Mx $v.Mx }
            if ($Options.CheckDane) { $v.Dane = Get-DaneAssessment -Domain $Domain -Context $ctx -Mx $v.Mx }
            if ($Options.CheckDnssec) { $v.Dnssec = Get-DnssecAssessment -Domain $Domain -Context $ctx }
            $v.Other = Get-OtherRecords -Domain $Domain -Context $ctx -ScopeDomain $Options.ScopeDomain
            foreach ($k in @('Mx', 'Spf', 'Dkim', 'Dmarc', 'MtaSts', 'Dane', 'Dnssec', 'Other')) { if ($v[$k]) { foreach ($f in $v[$k].Findings) { $found.Add($f) } } }
        }
        $failed = @($ctx.Log | Where-Object { -not (Test-ResolvedStatus $_.Status) } | Group-Object { "$($_.Name) $($_.Type)" })
        foreach ($g in $failed) { $found.Add((New-Finding -RuleId 'DNS-001' -Domain $Domain -Target $g.Name -Message "$($g.Name): $($g.Group[0].Status) $($g.Group[0].Message)")) }
        foreach ($f in $found) { $f.Vantage = $ctx.Vantage; $allFindings.Add($f) }
        $checks[$ctx.Vantage] = [pscustomobject]$v
        $seen = @{}
        foreach ($q in $ctx.Log) {
            $k = "$($q.Name)|$($q.Type)|$($q.DnssecOk)|$($q.CheckingDisabled)"
            if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $log.Add($q) }
        }
        $ctx.Log = $null
    }
    $diff = @()
    if ($Context.Count -gt 1) {
        $diff = @(Compare-Vantage -Query @($log))
        foreach ($f in @(Get-VantageFinding -Domain $Domain -Diff $diff)) { $f.Vantage = 'Both'; $allFindings.Add($f) }
        if ($Options.CheckDnssec -and $checks['Internal'].Dnssec -and $checks['External'].Dnssec -and $checks['Internal'].Dnssec.State -ne $checks['External'].Dnssec.State) {
            $f = New-Finding -RuleId 'DNSSEC-004' -Domain $Domain -Message "Internal: $($checks['Internal'].Dnssec.State); external: $($checks['External'].Dnssec.State)"
            $f.Vantage = 'Both'
            $allFindings.Add($f)
        }
    }
    $findings = Merge-VantageFinding @($allFindings)
    $records = foreach ($q in $log) {
        $rows = @($q.Records)
        if ($rows.Count -eq 0) { $rows = @([pscustomobject]@{ Name = $q.Name; Type = $q.Type; TTL = $null; Data = $null }) }
        foreach ($rec in $rows) {
            [pscustomobject]@{
                Vantage = $q.Vantage; Resolver = $q.Resolver; Query = $q.Name; QueryType = $q.Type; DnssecOk = $q.DnssecOk; Status = $q.Status
                AD = $(if ($q.DnssecOk) { $q.Authenticated } else { $null }); Name = $rec.Name; Type = $rec.Type; TTL = $rec.TTL; Data = $rec.Data
            }
        }
    }
    [pscustomobject]@{
        Domain      = $Domain
        Summary     = Get-DomainSummary -Domain $Domain -Checks $checks -Finding $findings
        Findings    = @($findings)
        Checks      = [pscustomobject]$checks
        Records     = @($records)
        VantageDiff = @($diff | Where-Object { $_.Result -ne 'Identical' })
        Identical   = @($diff | Where-Object { $_.Result -eq 'Identical' }).Count
    }
}

function Get-DomainInput {
    param([string]$DomainList, [string[]]$Domain)
    $raw = [System.Collections.Generic.List[string]]::new()
    if ($DomainList) {
        if (-not (Test-Path -LiteralPath $DomainList)) { throw "Domain list not found: $DomainList" }
        foreach ($line in (Get-Content -LiteralPath $DomainList)) { $raw.Add(($line -split '#', 2)[0]) }
    }
    foreach ($d in $Domain) { foreach ($p in ($d -split '[,;\s]+')) { $raw.Add($p) } }
    $idn = New-Object System.Globalization.IdnMapping
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $raw) {
        $d = ConvertTo-DnsName $r
        if (-not $d) { continue }
        if ($d -match '[^\x00-\x7F]') { $d = $idn.GetAscii($d) }
        if ($d -notmatch '^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$') { Write-Warning "Skipping invalid domain '$r'"; continue }
        if (-not $out.Contains($d)) { $out.Add($d) }
    }
    @($out)
}

#endregion

#region Sanitisation

function New-SanitizeMap {
    param([string[]]$Domain, [string[]]$MxHost, [string[]]$Selector)
    $map = @{
        Domains = [ordered]@{}; Names = @{}; Counters = @{}; MxHosts = @{}
        Static = @('spf.protection.outlook.com', 'spf.protection.office365.us', 'autodiscover.outlook.com', 'autodiscover-s.outlook.com', 'outlook.com',
            'mail.protection.outlook.com', 'mx.microsoft', 'dkim.mail.microsoft', 'onmicrosoft.com', '_spf.google.com', '_netblocks.google.com',
            '_netblocks2.google.com', '_netblocks3.google.com', 'sipdir.online.lync.com', 'sipfed.online.lync.com', 'webdir.online.lync.com',
            'enterpriseregistration.windows.net', 'enterpriseenrollment.manage.microsoft.com', 'enterpriseenrollment-s.manage.microsoft.com',
            'clientconfig.microsoftonline-p.net', 'mta-sts.txt')
        Providers = @('mail.protection.outlook.com', 'protection.outlook.com', 'outlook.com', 'mail.protection.office365.us', 'office365.us', 'mx.microsoft',
            'dkim.mail.microsoft', 'mail.onmicrosoft.com', 'onmicrosoft.com', 'onmicrosoft.us', 'online.lync.com', 'lync.com', 'microsoft.com', 'office.com',
            'microsoftonline.com', 'microsoftonline-p.net', 'windows.net', 'google.com', 'googlemail.com', 'amazonses.com', 'amazonaws.com', 'sendgrid.net',
            'mailgun.org', 'mcsv.net', 'mandrillapp.com', 'rsgsv.net', 'mimecast.com', 'pphosted.com', 'ppe-hosted.com', 'messagelabs.com',
            'barracudanetworks.com', 'iphmx.com', 'mailcontrol.com', 'trendmicro.com', 'hornetsecurity.com', 'sophos.com', 'salesforce.com', 'zendesk.com')
        Structural = @('selector1', 'selector2', 'autodiscover', 'mta-sts', 'lyncdiscover', 'sip', 'enterpriseregistration', 'enterpriseenrollment',
            'msoid', 'spf', 'mx', 'include', 'servers', 'sipdir', 'sipfed', 'webdir', 'clientconfig')
        PublicIps = @('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '2606:4700:4700::1111', '2001:4860:4860::8888', '2620:fe::fe')
    }
    $i = 0
    foreach ($d in $Domain) { $i++; $map.Domains[$d] = 'domain-{0:D2}' -f $i }
    foreach ($h in $MxHost) { if ($h) { $map.MxHosts[(ConvertTo-DnsName $h)] = $true } }
    $map.Structural += @($Selector | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
    $map
}

function Get-Pseudonym {
    param([hashtable]$Map, [string]$Role, [string]$Key)
    $k = "$Role|$Key"
    if (-not $map.Names.ContainsKey($k)) {
        $map.Counters[$Role] = 1 + [int]$map.Counters[$Role]
        $map.Names[$k] = '{0}-{1:D2}' -f $Role, $map.Counters[$Role]
    }
    $map.Names[$k]
}

function Get-DomainPseudonymText {
    # Replaces whole-token occurrences of input domains (dotted and dashed form).
    param([string]$Text, [hashtable]$Map)
    foreach ($d in ($Map.Domains.Keys | Sort-Object { $_.Length } -Descending)) {
        $p = $Map.Domains[$d]
        $Text = [regex]::Replace($Text, '(?i)(?<![a-z0-9-])' + [regex]::Escape($d) + '(?![a-z0-9-])', $p)
        $Text = [regex]::Replace($Text, '(?i)(?<![a-z0-9])' + [regex]::Escape($d.Replace('.', '-')) + '(?![a-z0-9])', $p)
    }
    $Text
}

function Get-SanitizedHostName {
    param([string]$Name, [hashtable]$Map)
    $n = ConvertTo-DnsName $Name
    $role = if ($Map.MxHosts.ContainsKey($n)) { 'mx' } else { 'host' }
    if ($Map.Domains.Contains($n)) { return $Map.Domains[$n] }
    if ($n -match '^(?<svc>(?:_[a-z0-9-]+\.)+)(?<rest>[^_].*)$') { return $Matches['svc'] + (Get-SanitizedHostName -Name $Matches['rest'] -Map $Map) }
    $structural = { param($labels) @($labels | Where-Object { -not ($_.StartsWith('_') -or $Map.Structural -contains $_ -or $_ -match '^domain-\d+$' -or $_ -match '^[a-z0-9]-v\d+$') }).Count -eq 0 }
    foreach ($d in ($Map.Domains.Keys | Sort-Object { $_.Length } -Descending)) {
        if ($n.EndsWith(".$d")) {
            $left = Get-DomainPseudonymText -Text $n.Substring(0, $n.Length - $d.Length - 1) -Map $Map
            if (& $structural ($left -split '\.')) { return "$left.$($Map.Domains[$d])" }
            return '{0}.{1}' -f (Get-Pseudonym $Map $role $n), $Map.Domains[$d]
        }
    }
    if ($Map.Static -contains $n) { return $n }
    foreach ($p in ($Map.Providers | Sort-Object { $_.Length } -Descending)) {
        if ($n -ne $p -and -not $n.EndsWith(".$p")) { continue }
        if ($n -eq $p) { return $n }
        $left = $n.Substring(0, $n.Length - $p.Length - 1)
        if ($left -match '^(?<sel>[^.]+)\._domainkey\.(?<tenant>[^.]+)(?<shard>\.[a-z0-9]-v\d+)?$') {
            $sel = $Matches['sel']; $tenant = $Matches['tenant']; $shard = $Matches['shard']
            $selOut = if ($sel -match '^(selector\d+)-') { "$($Matches[1])-" + (Get-Pseudonym $Map 'key' $sel) } else { Get-Pseudonym $Map 'key' $sel }
            return '{0}._domainkey.{1}{2}.{3}' -f $selOut, (Get-Pseudonym $Map 'tenant' $tenant), $shard, $p
        }
        if ($p -like '*onmicrosoft.*' -and $left -notmatch '\.') { return '{0}.{1}' -f (Get-Pseudonym $Map 'tenant' $left), $p }
        $labels = @($left -split '\.')
        if (& $structural $labels) { return $n }
        $keep = @($labels | Select-Object -Skip 1 | Where-Object { $_ -match '^[a-z0-9]-v\d+$' })
        $prefix = Get-Pseudonym $Map $role $n
        if ($keep.Count) { return '{0}.{1}.{2}' -f $prefix, ($keep -join '.'), $p }
        return "$prefix.$p"
    }
    Get-Pseudonym $Map $role $n
}

function ConvertTo-MaskedIp {
    param([string]$Address, [string]$Prefix, [hashtable]$Map)
    if ($Map.PublicIps -contains $Address) { return $(if ($Prefix) { "$Address/$Prefix" } else { $Address }) }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ip)) { return $Address }
    $isV4 = $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
    $limit = if ($isV4) { 24 } else { 48 }
    if ($Prefix -and [int]$Prefix -le $limit) { return "$Address/$Prefix" }
    $bytes = $ip.GetAddressBytes()
    $keep = $limit / 8
    for ($i = $keep; $i -lt $bytes.Length; $i++) { $bytes[$i] = 0 }
    '{0}/{1}' -f ([System.Net.IPAddress]::new($bytes)).ToString(), $limit
}

function ConvertTo-SanitizedString {
    param([string]$Text, [hashtable]$Map)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    # Secrets and identifiers first: DKIM keys, verification token values, hashes, GUIDs.
    $t = [regex]::Replace($t, '(?i)(\bp=)[A-Za-z0-9+/=\s]{16,}', '${1}[key]')
    $t = [regex]::Replace($t, '(?i)\b(MS|docusign|[a-z0-9._-]*(?:verif|validat|ownership|domain-key|site-key)[a-z0-9._-]*)([=:])[^\s;"\x27()]{4,}', '$1$2[token]')
    $t = [regex]::Replace($t, '\b[0-9a-fA-F]{40,}\b', '[hash]')
    $t = [regex]::Replace($t, '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '[guid]')
    # Mailboxes keep the (pseudonymised) domain only.
    $t = [regex]::Replace($t, '(?i)[a-z0-9._%+\-]+@(?=[a-z0-9_-]+\.)', 'mailbox@')
    # Host names.
    $t = [regex]::Replace($t, '(?i)(?<![a-z0-9_\-.])((?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9\-]{0,61}[a-z0-9])\.?(?![a-z0-9_\-])', {
            param($m)
            Get-SanitizedHostName -Name $m.Groups[1].Value -Map $Map
        })
    # IP addresses.
    $t = [regex]::Replace($t, '(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?![\d.])', {
            param($m)
            ConvertTo-MaskedIp -Address $m.Groups[1].Value -Prefix $m.Groups[2].Value -Map $Map
        })
    $t = [regex]::Replace($t, '(?i)(?<![0-9a-z:.])([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})(?:/(\d{1,3}))?(?![0-9a-z:])', {
            param($m)
            $ip = $null
            if ([System.Net.IPAddress]::TryParse($m.Groups[1].Value, [ref]$ip) -and $ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                ConvertTo-MaskedIp -Address $m.Groups[1].Value -Prefix $m.Groups[2].Value -Map $Map
            }
            else { $m.Value }
        })
    Get-DomainPseudonymText -Text $t -Map $Map
}

function ConvertTo-Sanitized {
    # Returns a sanitised deep copy of the result graph (strings rewritten, structure kept).
    param($InputObject, [hashtable]$Map)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [string]) { return (ConvertTo-SanitizedString -Text $InputObject -Map $Map) }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $copy = [ordered]@{}
        foreach ($k in $InputObject.Keys) { $copy[$k] = ConvertTo-Sanitized -InputObject $InputObject[$k] -Map $Map }
        return $copy
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        $items = foreach ($i in $InputObject) { , (ConvertTo-Sanitized -InputObject $i -Map $Map) }
        return , @($items)
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $copy = [ordered]@{}
        foreach ($p in $InputObject.PSObject.Properties) { $copy[$p.Name] = ConvertTo-Sanitized -InputObject $p.Value -Map $Map }
        return [pscustomobject]$copy
    }
    $InputObject
}

function Test-SanitizedText {
    # True when no input domain (dotted or dashed form) remains as a whole token.
    param([string]$Text, [hashtable]$Map)
    foreach ($d in $Map.Domains.Keys) {
        if ($Text -match ('(?i)(?<![a-z0-9-])' + [regex]::Escape($d) + '(?![a-z0-9-])')) { return $false }
        if ($Text -match ('(?i)(?<![a-z0-9])' + [regex]::Escape($d.Replace('.', '-')) + '(?![a-z0-9])')) { return $false }
    }
    $true
}

#endregion

#region Reports

function ConvertTo-MdCell {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.Array]) { $Value = $Value -join ', ' }
    ([string]$Value) -replace '\|', '\|' -replace '\r?\n', ' '
}

function ConvertTo-MdTable {
    param([object[]]$Rows, [string[]]$Columns)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('| ' + ($Columns -join ' | ') + ' |')
    $lines.Add('|' + (($Columns | ForEach-Object { ' --- ' }) -join '|') + '|')
    foreach ($r in $Rows) { $lines.Add('| ' + (($Columns | ForEach-Object { ConvertTo-MdCell $r.$_ }) -join ' | ') + ' |') }
    $lines
}

function ConvertTo-MarkdownReport {
    param([object[]]$Result, $Meta)
    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add('# Mail DNS and authentication assessment')
    $md.Add('')
    $md.Add("- Generated (UTC): $($Meta.GeneratedUtc)")
    $md.Add("- Script version: $($Meta.ScriptVersion); PowerShell $($Meta.PowerShell)")
    $md.Add("- Vantage: $($Meta.Vantage); internal resolvers: $($Meta.InternalResolver -join ', '); external resolvers: $($Meta.ExternalResolver -join ', ')")
    $md.Add("- Checks: MTA-STS $($Meta.CheckMtaSts); DANE $($Meta.CheckDane); DNSSEC $($Meta.CheckDnssec); DKIM selectors $($Meta.DkimSelector -join ', ')")
    $md.Add("- Sanitized: $($Meta.Sanitized)")
    $md.Add('')
    $md.Add('## Summary')
    $md.Add('')
    $cols = @('Domain', 'MxClass', 'SpfLookups', 'SpfAll', 'DkimSelector1', 'DkimSelector2', 'DmarcP', 'DmarcSp', 'DmarcPct', 'MtaSts', 'Dane', 'Dnssec', 'Critical', 'High', 'Medium', 'Info')
    foreach ($l in (ConvertTo-MdTable -Rows @($Result | ForEach-Object { $_.Summary }) -Columns $cols)) { $md.Add($l) }
    foreach ($r in $Result) {
        $md.Add('')
        $md.Add("## $($r.Domain)")
        $md.Add('')
        $md.Add('### Findings')
        $md.Add('')
        if ($r.Findings.Count) { foreach ($l in (ConvertTo-MdTable -Rows $r.Findings -Columns @('Severity', 'RuleId', 'Check', 'Vantage', 'Target', 'Message', 'Recommendation'))) { $md.Add($l) } }
        else { $md.Add('No findings.') }
        $pv = $r.Summary.Vantage
        $c = $r.Checks.$pv
        if ($c -and $c.Exists) {
            if ($c.Spf -and $c.Spf.Terms.Count) {
                $md.Add('')
                $md.Add("### SPF expansion ($pv): $($c.Spf.Lookups) lookups, $($c.Spf.VoidLookups) void")
                $md.Add('')
                foreach ($l in (ConvertTo-MdTable -Rows $c.Spf.Terms -Columns @('Depth', 'Source', 'Qualifier', 'Mechanism', 'Value', 'CountsLookup'))) { $md.Add($l) }
                if ($c.Spf.IpRanges.Count) {
                    $md.Add('')
                    $md.Add('IP ranges: ' + (($c.Spf.IpRanges | ForEach-Object { "$($_.Qualifier)$($_.Range) ($($_.Source))" }) -join ', '))
                }
            }
            if ($c.Dkim) {
                $md.Add('')
                $md.Add("### DKIM ($pv)")
                $md.Add('')
                foreach ($l in (ConvertTo-MdTable -Rows $c.Dkim.Selectors -Columns @('Selector', 'RecordType', 'CnameTarget', 'CnameClass', 'KeyType', 'Bits', 'Revoked', 'TTL'))) { $md.Add($l) }
            }
            if ($c.Dmarc -and $c.Dmarc.Record) {
                $md.Add('')
                $md.Add("### DMARC ($pv)")
                $md.Add('')
                $md.Add('`' + $c.Dmarc.Record + '`')
                if ($c.Dmarc.ReportAuthorization.Count) {
                    $md.Add('')
                    foreach ($l in (ConvertTo-MdTable -Rows $c.Dmarc.ReportAuthorization -Columns @('Destination', 'Record', 'Status', 'Authorized'))) { $md.Add($l) }
                }
            }
            if ($c.MtaSts -and $c.MtaSts.Policy) {
                $p = $c.MtaSts.Policy
                $md.Add('')
                $md.Add("### MTA-STS ($pv)")
                $md.Add('')
                $md.Add("mode $($p.Mode); max_age $($p.MaxAge); mx $($p.Mx -join ', '); id $($c.MtaSts.Id)")
                if ($c.MtaSts.Certificate -and $c.MtaSts.Certificate.Retrieved) { $md.Add("Certificate: $($c.MtaSts.Certificate.Subject); expires $($c.MtaSts.Certificate.NotAfter); valid $($c.MtaSts.Certificate.Valid)") }
            }
        }
        $md.Add('')
        $md.Add('### Records')
        $md.Add('')
        foreach ($l in (ConvertTo-MdTable -Rows $r.Records -Columns @('Vantage', 'Resolver', 'Query', 'QueryType', 'DnssecOk', 'Status', 'Type', 'TTL', 'Data', 'AD'))) { $md.Add($l) }
        if (@($r.Checks.PSObject.Properties).Count -gt 1) {
            $md.Add('')
            $md.Add("### Cross-vantage diff ($($r.Identical) identical)")
            $md.Add('')
            if ($r.VantageDiff.Count) { foreach ($l in (ConvertTo-MdTable -Rows $r.VantageDiff -Columns @('Name', 'Type', 'Result', 'InternalData', 'ExternalData', 'InternalTTL', 'ExternalTTL'))) { $md.Add($l) } }
            else { $md.Add('No differences.') }
        }
    }
    $md -join "`n"
}

function Export-Report {
    param([object[]]$Result, $Meta, [string]$OutputPath, [switch]$Sanitize)
    if (-not (Test-Path -LiteralPath $OutputPath)) { [void](New-Item -ItemType Directory -Path $OutputPath -Force) }
    $data = $Result
    $metaOut = $Meta
    if ($Sanitize) {
        $mxHosts = @($Result | ForEach-Object { $c = $_.Checks; foreach ($p in $c.PSObject.Properties) { if ($p.Value.Mx) { $p.Value.Mx.Hosts | ForEach-Object { $_.Host } } } })
        $map = New-SanitizeMap -Domain @($Result | ForEach-Object { $_.Domain }) -MxHost $mxHosts -Selector $Meta.DkimSelector
        $data = ConvertTo-Sanitized -InputObject $Result -Map $map
        $metaOut = ConvertTo-Sanitized -InputObject $Meta -Map $map
    }
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $base = Join-Path $OutputPath "assessment-$stamp"
    # Windows PowerShell 5.1 serialises PSObject-wrapped arrays as {"value":...,"Count":...} while the
    # System.Array type data is loaded; remove it for the conversion and restore it afterwards.
    $arrayTypeData = $null
    if ($PSVersionTable.PSEdition -ne 'Core') {
        $arrayTypeData = Get-TypeData -TypeName System.Array
        if ($arrayTypeData) { Remove-TypeData -TypeName System.Array }
    }
    try { $json = ConvertTo-Json -InputObject ([pscustomobject]@{ Meta = $metaOut; Domains = @($data) }) -Depth 12 }
    finally { if ($arrayTypeData) { Update-TypeData -TypeData $arrayTypeData -Force } }
    $csv = (@($data | ForEach-Object { $_.Summary }) | ConvertTo-Csv -NoTypeInformation) -join "`r`n"
    $md = ConvertTo-MarkdownReport -Result $data -Meta $metaOut
    if ($Sanitize) {
        foreach ($text in @($json, $csv, $md)) { if (-not (Test-SanitizedText -Text $text -Map $map)) { throw 'Sanitisation check failed: an input domain is still present. No report written.' } }
    }
    $enc = New-Object System.Text.UTF8Encoding($false)
    $paths = [ordered]@{ Json = "$base.json"; Csv = "$base.csv"; Markdown = "$base.md" }
    [System.IO.File]::WriteAllText($paths.Json, $json, $enc)
    [System.IO.File]::WriteAllText($paths.Csv, $csv, $enc)
    [System.IO.File]::WriteAllText($paths.Markdown, $md, $enc)
    [pscustomobject]$paths
}

#endregion

#region Orchestrator entry

function Get-MailDnsAssessmentVersion {
    $script:ModuleVersion
}

function Invoke-Assessment {
    [CmdletBinding()]
    param(
        [string[]]$DomainName, [string]$Vantage = 'Both', [string[]]$InternalResolver, [string[]]$ExternalResolver,
        [string[]]$DkimSelector, [switch]$CheckMtaSts, [switch]$CheckDane, [switch]$CheckDnssec,
        [string]$OutputPath, [switch]$Sanitize, [int]$TimeoutSeconds = 5, [string]$ScriptVersion
    )
    if ($PSVersionTable.PSEdition -ne 'Core') {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    $engine = if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) { 'DnsClient' } else { 'Wire' }
    if ($engine -eq 'Wire') { Write-Warning 'Resolve-DnsName is not available; using the built-in socket resolver for all queries.' }
    $cache = @{}
    $contexts = [System.Collections.Generic.List[hashtable]]::new()
    if ($Vantage -in @('Internal', 'Both')) {
        if (-not $InternalResolver) { $InternalResolver = Get-SystemDnsResolver }
        if ($InternalResolver) { $contexts.Add(@{ Vantage = 'Internal'; Resolvers = @($InternalResolver); TimeoutSeconds = $TimeoutSeconds; Engine = $engine; Cache = $cache; Health = @{}; Log = $null }) }
        else { Write-Warning 'No internal resolver found; the internal vantage is skipped.' }
    }
    if ($Vantage -in @('External', 'Both')) {
        $contexts.Add(@{ Vantage = 'External'; Resolvers = @($ExternalResolver); TimeoutSeconds = $TimeoutSeconds; Engine = $engine; Cache = $cache; Health = @{}; Log = $null })
    }
    if ($contexts.Count -eq 0) { throw 'No resolver available.' }
    $options = @{ ScopeDomain = $DomainName; DkimSelector = $DkimSelector; CheckMtaSts = [bool]$CheckMtaSts; CheckDane = [bool]$CheckDane; CheckDnssec = [bool]$CheckDnssec }
    $results = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $DomainName.Count; $i++) {
        Write-Progress -Activity 'Mail DNS assessment' -Status "$($DomainName[$i]) ($($i + 1)/$($DomainName.Count))" -PercentComplete ([int](100 * $i / $DomainName.Count))
        $results.Add((Invoke-DomainAssessment -Domain $DomainName[$i] -Context $contexts.ToArray() -Options $options))
    }
    Write-Progress -Activity 'Mail DNS assessment' -Completed
    if ($script:DnsClientRunspace) { $script:DnsClientRunspace.Dispose(); $script:DnsClientRunspace = $null }
    $meta = [pscustomobject]@{
        Tool = 'Invoke-MailDnsAssessment'; ScriptVersion = $ScriptVersion; GeneratedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        PowerShell = $PSVersionTable.PSVersion.ToString(); Engine = $engine; Vantage = $Vantage
        InternalResolver = @($contexts | Where-Object { $_.Vantage -eq 'Internal' } | ForEach-Object { $_.Resolvers }); ExternalResolver = @($contexts | Where-Object { $_.Vantage -eq 'External' } | ForEach-Object { $_.Resolvers })
        DkimSelector = @(@('selector1', 'selector2') + @($DkimSelector) | Where-Object { $_ } | Select-Object -Unique)
        CheckMtaSts = [bool]$CheckMtaSts; CheckDane = [bool]$CheckDane; CheckDnssec = [bool]$CheckDnssec; Sanitized = [bool]$Sanitize; TimeoutSeconds = $TimeoutSeconds
    }
    $paths = Export-Report -Result $results.ToArray() -Meta $meta -OutputPath $OutputPath -Sanitize:$Sanitize
    [pscustomobject]@{ Results = $results.ToArray(); Paths = $paths }
}
#endregion

Export-ModuleMember -Function Invoke-Assessment, Get-DomainInput, Get-MailDnsAssessmentVersion

# Version: 1
