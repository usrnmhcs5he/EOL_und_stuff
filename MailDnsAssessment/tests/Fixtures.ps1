# Test fixtures: throwaway DKIM keys, fake DNS zones for an internal and an external
# vantage, and fake query engines that answer from those zones instead of the network.
# Dot-source after _TestHelpers.ps1 so the fakes replace the real engine functions.

$FixtureKeys = @{
    Spki512     = 'MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALVgL9EIYQltZxQ6CkZhm/8199aM0iQqhTmVRHdGWENGImPnoT0O1IHuyelh8iXraSCj1CacHIiIuDkHeyVixLcCAwEAAQ=='
    Spki1024    = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDT9Jm9fFiSNpM+QZuOvw9JxsgzCrcxxtN+NhF+A0+uKpzVz+qT4C6Y6xr7e00M45l5iZjqL5Pq1iwHuCDjwuXUJ0YVlxv0xstp/c2eP4etHeArm+oO4fFuNGeYLlAjn07+grbraJRtiO8VdF6J7+jJwrhsuGAvx2EBwdZZl9HOkwIDAQAB'
    Spki2048    = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1ah6n8pn2uQDJpyxXoXcsGkpX2jEC9yPHJZoIUidHhmVqgvYb2EQHCtyVOiittcYnDRKzZvlH7n/SGlHgcpr8FgOz1zUJwELAVhF6w3V4GYToVZU+Xy+QFVOYuSF3roC2JaSIFCxJJrHe/9o/oAW1LKy+X37w4TapSHtkCpcD55SKkjhyggviyJtpGkZ32dse/vgrcxM/aQtL9WgWx6ZZyx57ANFRBwEPM1TbGTNqXEOAmHcHfxCyANInQKn4iCJRE2zSAwiFR9mz1eS/zcnXMGdjwCoy6urlZ1R2J09aih/wlF2yjQTdnlUJwPyT0hwj/Siz4lKdRmM+3kdmMIbawIDAQAB'
    Spki4096    = 'MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAkkriKAsOHy8ucwuBszsWdGOPd9QMTfYSDJDbrehFHAv22FfprHgWi7Mrb7fZZ2aqK/YiUYGp7ObdixTGaEqeUJgpAkqANVnl5ecdbuNn6IrRP7XMMBvO2qd356IISlwp6XNi8XaOh7VkXpNd2hDwiM7QxB8DqHibIaMUMwgnNOhuVqS7J/EVOZrkYRgMNleM6SWnrXDih1nCCQ3w2Hlrkixq46reKGXP94wkQnhxQM+Cgy0tXiFJuaQLPAHXn0/ximvtWKNvHY0bPfzNmOJ4eEJYB9tvOOw1A8/P6qcd0ZAUodMFdIyw0uPxdx+mgIWUoAHtvhTpVRbwkUTMC4yYSVSW9WIvPujNMd/eVy3z1ySIwJfZYHLsE5Ro0JPjxD5n53JIO6syYz5pqThambgv/EOn3uqScsghnxkvC9gv749KBchVhBWO8Db4pRnX9mA3xyckiqZPiA0mz+0Yh3ZWgqS1ttHk9vtWuKWSW0z9XV44mR81tcqRQj5LEUhhm4k7ZjUdudiZqVdWAvBkeskZxT/rZhdrRM5yzqig/gyZdCaneYvdXShhJtB7v01fVoPD/XREGa/1xZPQXjd0TwVQzzM+Z+JWtXsBdPNkow7/YJisAxEyuArKa0xs7dm0cNkwSpQpT2+/T/5RY9P21dynTo7vbSlOpwjDmSmUCv6dZMMCAwEAAQ=='
    Pkcs1_2048  = 'MIIBCgKCAQEA1ah6n8pn2uQDJpyxXoXcsGkpX2jEC9yPHJZoIUidHhmVqgvYb2EQHCtyVOiittcYnDRKzZvlH7n/SGlHgcpr8FgOz1zUJwELAVhF6w3V4GYToVZU+Xy+QFVOYuSF3roC2JaSIFCxJJrHe/9o/oAW1LKy+X37w4TapSHtkCpcD55SKkjhyggviyJtpGkZ32dse/vgrcxM/aQtL9WgWx6ZZyx57ANFRBwEPM1TbGTNqXEOAmHcHfxCyANInQKn4iCJRE2zSAwiFR9mz1eS/zcnXMGdjwCoy6urlZ1R2J09aih/wlF2yjQTdnlUJwPyT0hwj/Siz4lKdRmM+3kdmMIbawIDAQAB'
    Ed25519Raw  = '0+8LdNCB4ElktC5hPIh7E2FPU0RkcXqrS2OsCkAmd6Y='
    Ed25519Spki = 'MCowBQYDK2VwAyEA0+8LdNCB4ElktC5hPIh7E2FPU0RkcXqrS2OsCkAmd6Y='
}

function Add-FixtureRecord {
    param([hashtable]$Zone, [string]$Name, [string]$Type, [int]$TTL, [string[]]$Data)
    $records = foreach ($d in $Data) {
        switch ($Type) {
            'MX' { $p = $d -split ' ', 2; New-DnsRecordObject -Name $Name -Type MX -TTL $TTL -Data $d -Preference ([int]$p[0]) -Target $p[1] }
            'SRV' { $p = $d -split ' '; New-DnsRecordObject -Name $Name -Type SRV -TTL $TTL -Data $d -Priority ([int]$p[0]) -Weight ([int]$p[1]) -Port ([int]$p[2]) -Target $p[3] }
            { $_ -in @('CNAME', 'NS') } { New-DnsRecordObject -Name $Name -Type $Type -TTL $TTL -Data $d -Target $d }
            default { New-DnsRecordObject -Name $Name -Type $Type -TTL $TTL -Data $d }
        }
    }
    $Zone["$Name|$Type"] = @{ Status = 'NoError'; Records = @($records) }
}

$tlsaHash = '9db9c89a3c60784bb5b682d83243dd664112f1c625283e518dcc23f992a04051'
$ext = @{}
# example.com: mixed EOP/gateway MX, SPF without EOP, DKIM selector2 as 1024-bit TXT, weak DMARC.
Add-FixtureRecord $ext 'example.com' SOA 3600 'ns1.example.net hostmaster.example.com 2026102901'
Add-FixtureRecord $ext 'example.com' NS 3600 'ns1.example.net'
Add-FixtureRecord $ext 'example.com' MX 7200 @('10 example-com.mail.protection.outlook.com', '20 mx1.gateway.example.net')
Add-FixtureRecord $ext 'example.com' A 3600 '203.0.113.5'
Add-FixtureRecord $ext 'example.com' TXT 3600 @('v=spf1 include:_spf.example.net ip4:203.0.113.0/24 a mx ~all', 'MS=ms12345678', 'MS=ms87654321', 'google-site-verification=abcdefghijklmnop')
Add-FixtureRecord $ext 'example-com.mail.protection.outlook.com' A 10 '192.0.2.10'
Add-FixtureRecord $ext 'mx1.gateway.example.net' A 300 '198.51.100.25'
Add-FixtureRecord $ext '_spf.example.net' TXT 3600 'v=spf1 ip4:198.51.100.0/24 include:missing.example.net -all'
Add-FixtureRecord $ext 'spf.protection.outlook.com' TXT 3600 'v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip6:2a01:111:f400::/48 include:spfd.protection.outlook.com -all'
Add-FixtureRecord $ext 'spfd.protection.outlook.com' TXT 3600 'v=spf1 ip4:52.100.0.0/15 -all'
Add-FixtureRecord $ext 'selector1._domainkey.example.com' CNAME 3600 'selector1-example-com._domainkey.tenant.onmicrosoft.com'
Add-FixtureRecord $ext 'selector1-example-com._domainkey.tenant.onmicrosoft.com' TXT 3600 "v=DKIM1; k=rsa; p=$($FixtureKeys.Spki2048)"
Add-FixtureRecord $ext 'selector2._domainkey.example.com' TXT 3600 "v=DKIM1; k=rsa; p=$($FixtureKeys.Spki1024)"
Add-FixtureRecord $ext '_dmarc.example.com' TXT 3600 'v=DMARC1; p=none; pct=50; rua=mailto:dmarc@reports.example.org; ruf=mailto:forensic@example.com'
Add-FixtureRecord $ext '_mta-sts.example.com' TXT 3600 'v=STSv1; id=20260101T000000;'
Add-FixtureRecord $ext '_25._tcp.mx1.gateway.example.net' TLSA 3600 "3 1 1 $tlsaHash"
Add-FixtureRecord $ext 'autodiscover.example.com' CNAME 3600 'autodiscover.outlook.com'
Add-FixtureRecord $ext 'msoid.example.com' CNAME 3600 'clientconfig.microsoftonline-p.net'
Add-FixtureRecord $ext 'lyncdiscover.example.com' CNAME 3600 'webdir.online.lync.com'
# example.net: clean EOP configuration with DANE and a signed zone.
Add-FixtureRecord $ext 'example.net' SOA 3600 'ns1.example.net hostmaster.example.net 2026102901'
Add-FixtureRecord $ext 'example.net' NS 3600 'ns1.example.net'
Add-FixtureRecord $ext 'example.net' MX 3600 '0 example-net.o-v1.mx.microsoft'
Add-FixtureRecord $ext 'example.net' TXT 3600 'v=spf1 include:spf.protection.outlook.com -all'
Add-FixtureRecord $ext 'example-net.o-v1.mx.microsoft' A 10 '192.0.2.20'
Add-FixtureRecord $ext 'selector1._domainkey.example.net' CNAME 3600 'selector1-example-net01b._domainkey.tenant.k-v1.dkim.mail.microsoft'
Add-FixtureRecord $ext 'selector2._domainkey.example.net' CNAME 3600 'selector2-example-net01b._domainkey.tenant.k-v1.dkim.mail.microsoft'
Add-FixtureRecord $ext 'selector1-example-net01b._domainkey.tenant.k-v1.dkim.mail.microsoft' TXT 3600 "v=DKIM1; k=rsa; p=$($FixtureKeys.Spki2048)"
Add-FixtureRecord $ext 'selector2-example-net01b._domainkey.tenant.k-v1.dkim.mail.microsoft' TXT 3600 "v=DKIM1; k=rsa; p=$($FixtureKeys.Spki4096)"
Add-FixtureRecord $ext '_dmarc.example.net' TXT 3600 'v=DMARC1; p=reject; rua=mailto:dmarc@example.net'
Add-FixtureRecord $ext '_mta-sts.example.net' TXT 3600 'v=STSv1; id=2026a'
Add-FixtureRecord $ext '_smtp._tls.example.net' TXT 3600 'v=TLSRPTv1; rua=mailto:tlsrpt@example.net'
Add-FixtureRecord $ext '_25._tcp.example-net.o-v1.mx.microsoft' TLSA 3600 "3 1 1 $tlsaHash"
Add-FixtureRecord $ext 'autodiscover.example.net' CNAME 3600 'autodiscover.outlook.com'

# Internal view: stale copy of example.com (gateway-only MX, older serial, on-premises autodiscover).
$int = @{}
foreach ($k in $ext.Keys) { $int[$k] = $ext[$k] }
Add-FixtureRecord $int 'example.com' SOA 3600 'ns1.example.net hostmaster.example.com 2026090101'
Add-FixtureRecord $int 'example.com' MX 7200 '10 mx1.gateway.example.net'
$int.Remove('autodiscover.example.com|CNAME')
Add-FixtureRecord $int 'autodiscover.example.com' A 3600 '10.1.2.3'

$FixtureZones = @{ External = $ext; Internal = $int }
$FixtureSignedZones = @('example.net', 'mx.microsoft')
$FixtureUnsignedZones = @('gateway.example.net')   # insecure delegation below a signed zone
$FixturePolicies = @{
    'example.com' = "version: STSv1`nmode: enforce`nmx: mx1.gateway.example.net`nmax_age: 3600`n"
    'example.net' = "version: STSv1`r`nmode: enforce`r`nmx: example-net.o-v1.mx.microsoft`r`nmax_age: 604800`r`n"
}

function Get-FixtureAnswer {
    param([string]$Name, [string]$Type, [string]$Vantage)
    $zone = $FixtureZones[$Vantage]
    if ($zone.ContainsKey("$Name|$Type")) { $e = $zone["$Name|$Type"]; return [pscustomobject]@{ Status = $e.Status; Records = @($e.Records) } }
    if ($Type -ne 'CNAME' -and $zone.ContainsKey("$Name|CNAME")) {
        $c = $zone["$Name|CNAME"]
        $t = Get-FixtureAnswer -Name $c.Records[0].Target -Type $Type -Vantage $Vantage
        return [pscustomobject]@{ Status = $t.Status; Records = @($c.Records) + @($t.Records) }
    }
    if (@($zone.Keys | Where-Object { $_.StartsWith("$Name|") }).Count) { return [pscustomobject]@{ Status = 'NoError'; Records = @() } }
    [pscustomobject]@{ Status = 'NXDomain'; Records = @() }
}

function Get-FixtureVantage {
    param([string]$Server)
    if ($Server -like '10.*') { 'Internal' } else { 'External' }
}

function Invoke-DnsClientQuery {
    param([string]$Name, [string]$Type, [string]$Server, [int]$TimeoutSeconds)
    if ($Server -eq '10.0.0.99') { return [pscustomobject]@{ Status = 'Timeout'; Records = @(); Message = 'fixture timeout' } }
    $a = Get-FixtureAnswer -Name $Name -Type $Type -Vantage (Get-FixtureVantage $Server)
    [pscustomobject]@{ Status = $a.Status; Records = $a.Records; Message = $null }
}

function Invoke-DnsWireQuery {
    param([string]$Name, [string]$Type, [string]$Server, [int]$TimeoutSeconds = 5, [switch]$DnssecOk, [switch]$CheckingDisabled)
    if ($Server -eq '10.0.0.99') { return [pscustomobject]@{ Status = 'Timeout'; Records = @(); Authenticated = $null; Signed = $null; Message = 'fixture timeout' } }
    $vantage = Get-FixtureVantage $Server
    $a = Get-FixtureAnswer -Name $Name -Type $Type -Vantage $vantage
    $signed = @($FixtureSignedZones | Where-Object { Test-InDomain $Name $_ }).Count -gt 0
    if (@($FixtureUnsignedZones | Where-Object { Test-InDomain $Name $_ }).Count) { $signed = $false }
    [pscustomobject]@{
        Status        = $a.Status
        Records       = $a.Records
        Authenticated = [bool]($DnssecOk -and $signed -and $vantage -eq 'External')
        Signed        = [bool]($DnssecOk -and $signed)
        Message       = $null
    }
}

function Get-MtaStsPolicy {
    param([string]$Domain, [int]$TimeoutSeconds)
    $url = "https://mta-sts.$Domain/.well-known/mta-sts.txt"
    if ($FixturePolicies.ContainsKey($Domain)) { return [pscustomobject]@{ Url = $url; StatusCode = 200; ContentType = 'text/plain'; Content = $FixturePolicies[$Domain]; Error = $null } }
    [pscustomobject]@{ Url = $url; StatusCode = $null; ContentType = $null; Content = $null; Error = 'No such host is known.' }
}

function Get-TlsCertificateInfo {
    param([string]$HostName, [int]$Port = 443, [int]$TimeoutSeconds = 5)
    [pscustomobject]@{
        Host = $HostName; Retrieved = $true; Subject = "CN=$HostName"; Issuer = 'CN=Fixture CA'
        NotBefore = '2026-01-01T00:00:00.0000000Z'; NotAfter = '2027-06-01T00:00:00.0000000Z'; DaysRemaining = 200
        DnsNames = @($HostName); NameMatch = $true; PolicyErrors = 'None'; Valid = $true; Error = $null
    }
}
