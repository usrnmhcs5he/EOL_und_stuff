# DNS layer: wire format, Resolve-DnsName normalisation, error mapping, resolver failover.

Describe 'DNS wire format' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_TestHelpers.ps1')
        function ConvertFrom-Hex { param([string]$Hex) [byte[]]($Hex -split '(..)' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) }) }
    }

    It 'builds a query with EDNS0' {
        $hex = ((New-DnsQueryPacket -Name 'Example.com.' -TypeCode 1 -Id 0x1234) | ForEach-Object { $_.ToString('x2') }) -join ''
        Assert-Equal '123401000001000000000001076578616d706c6503636f6d0000010001000029' $hex.Substring(0, 64)
        Assert-Equal '04d0000000000000' $hex.Substring(64)
    }

    It 'sets AD, CD and DO when requested' {
        $q = New-DnsQueryPacket -Name 'example.com' -TypeCode 52 -Id 1 -DnssecOk -CheckingDisabled
        Assert-Equal 0x30 ([int]$q[3])
        Assert-Equal 0x80 ([int]$q[$q.Length - 4])
    }

    It 'parses answers with name compression, flags and RRSIG' {
        $m = ConvertFrom-DnsWireMessage (ConvertFrom-Hex '123481a00001000300000000076578616d706c6503636f6d00000f0001c00c000f00010000012c0008000a036d7831c00cc00c00100001ffffffff000d0568656c6c6f062d776f726c64c00c002e00010000012c0012000f00000000000000000000000000000000')
        Assert-Equal 0x1234 $m.Id
        Assert-True $m.AuthenticData
        Assert-Equal 0 $m.Rcode
        Assert-Equal 3 $m.Answers.Count
        Assert-Equal 'mx1.example.com' $m.Answers[0].Target
        Assert-Equal 10 $m.Answers[0].Preference
        Assert-Equal 300 $m.Answers[0].TTL
        Assert-Equal 'hello-world' $m.Answers[1].Data
        Assert-Equal 4294967295 $m.Answers[1].TTL
        Assert-Equal 'RRSIG' $m.Answers[2].Type
        Assert-Equal 'covers MX' $m.Answers[2].Data
    }

    It 'parses TLSA and reads truncation and rcode' {
        $t = ConvertFrom-DnsWireMessage (ConvertFrom-Hex '000183830001000000000000035f3235045f746370026d78076578616d706c6503636f6d0000340001')
        Assert-True $t.Truncated
        Assert-Equal 3 $t.Rcode
        $m = ConvertFrom-DnsWireMessage (ConvertFrom-Hex '000281800001000100000000035f3235045f746370026d78076578616d706c6503636f6d0000340001c00c00340001000002580023030101abababababababababababababababababababababababababababababababab')
        Assert-Equal ('3 1 1 ' + ('ab' * 32)) $m.Answers[0].Data
        Assert-Equal '_25._tcp.mx.example.com' $m.Answers[0].Name
        Assert-True (-not $m.AuthenticData)
    }
}

Describe 'Resolve-DnsName normalisation' {
    BeforeAll { . (Join-Path $PSScriptRoot '_TestHelpers.ps1') }

    It 'converts Resolve-DnsName shaped objects' {
        $mx = ConvertFrom-DnsClientRecord ([pscustomobject]@{ Name = 'example.com'; Type = 'MX'; TTL = 3600; Section = 'Answer'; NameExchange = 'MX1.Example.com.'; Preference = 10 })
        Assert-Equal 'mx1.example.com' $mx.Target
        Assert-Equal 10 $mx.Preference
        $txt = ConvertFrom-DnsClientRecord ([pscustomobject]@{ Name = 'example.com'; Type = 'TXT'; TTL = 300; Section = 'Answer'; Strings = @('v=spf1 ip4:192.0.2.0/24 ', '-all') })
        Assert-Equal 'v=spf1 ip4:192.0.2.0/24 -all' $txt.Data
        $srv = ConvertFrom-DnsClientRecord ([pscustomobject]@{ Name = '_autodiscover._tcp.example.com'; Type = 'SRV'; TTL = 60; Section = 'Answer'; NameTarget = 'mail.example.com'; Priority = 0; Weight = 0; Port = 443 })
        Assert-Equal '0 0 443 mail.example.com' $srv.Data
        $cname = ConvertFrom-DnsClientRecord ([pscustomobject]@{ Name = 'autodiscover.example.com'; Type = 5; TTL = 60; Section = 'Answer'; NameHost = 'autodiscover.outlook.com' })
        Assert-Equal 'CNAME' $cname.Type
        Assert-Equal 'autodiscover.outlook.com' $cname.Target
        $a = ConvertFrom-DnsClientRecord ([pscustomobject]@{ Name = 'example.com'; Type = 'A'; TTL = 60; Section = 'Answer'; IPAddress = '192.0.2.1' })
        Assert-Equal '192.0.2.1' $a.Data
    }

    It 'maps Resolve-DnsName errors to statuses' {
        Assert-Equal 'NXDomain' (ConvertFrom-DnsClientError -ErrorId 'DNS_ERROR_RCODE_NAME_ERROR,Microsoft.DnsClient.Commands.ResolveDnsName')
        Assert-Equal 'NoData' (ConvertFrom-DnsClientError -ErrorId 'DNS_INFO_NO_RECORDS,Microsoft.DnsClient.Commands.ResolveDnsName')
        Assert-Equal 'ServFail' (ConvertFrom-DnsClientError -ErrorId 'x' -NativeErrorCode 9002)
        Assert-Equal 'Timeout' (ConvertFrom-DnsClientError -ErrorId 'ERROR_TIMEOUT,Microsoft.DnsClient.Commands.ResolveDnsName')
        Assert-Equal 'Error' (ConvertFrom-DnsClientError -ErrorId 'SOMETHING_ELSE')
    }
}

Describe 'Resolve-Record' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_TestHelpers.ps1')
        . (Join-Path $PSScriptRoot 'Fixtures.ps1')
        function New-TestContext { @{ Vantage = 'Internal'; Resolvers = @('10.0.0.99', '10.0.0.53'); TimeoutSeconds = 1; Engine = 'DnsClient'; Cache = @{}; Health = @{}; Log = ([System.Collections.Generic.List[object]]::new()) } }
    }

    It 'fails over to the next resolver and records which one answered' {
        $ctx = New-TestContext
        $r = Resolve-Record -Name 'example.com' -Type MX -Context $ctx
        Assert-Equal 'NoError' $r.Status
        Assert-Equal '10.0.0.53' $r.Resolver
        Assert-Equal 7200 $r.Records[0].TTL
    }

    It 'moves a resolver that keeps timing out to the end' {
        $ctx = New-TestContext
        [void](Resolve-Record -Name 'example.com' -Type MX -Context $ctx)
        [void](Resolve-Record -Name 'example.com' -Type TXT -Context $ctx)
        Assert-Equal 2 $ctx.Health['10.0.0.99']
        [void](Resolve-Record -Name 'example.com' -Type SOA -Context $ctx)
        Assert-Equal 2 $ctx.Health['10.0.0.99']
    }

    It 'normalises NoData, NXDOMAIN and CNAME chains' {
        $ctx = New-TestContext
        Assert-Equal 'NoData' (Resolve-Record -Name 'example.com' -Type AAAA -Context $ctx).Status
        Assert-Equal 'NXDomain' (Resolve-Record -Name 'nothing.example.com' -Type TXT -Context $ctx).Status
        $ctx.Vantage = 'External'; $ctx.Resolvers = @('192.0.2.53')
        $c = Resolve-Record -Name 'selector1._domainkey.example.com' -Type TXT -Context $ctx
        Assert-Equal 'NoError' $c.Status
        Assert-Equal 'CNAME' $c.Records[0].Type
        Assert-Equal 'TXT' $c.Records[1].Type
    }

    It 'caches answers and still logs every use' {
        $ctx = New-TestContext
        $a = Resolve-Record -Name 'example.com' -Type MX -Context $ctx
        $b = Resolve-Record -Name 'example.com' -Type MX -Context $ctx
        Assert-True ([object]::ReferenceEquals($a, $b))
        Assert-Equal 2 $ctx.Log.Count
    }

    It 'uses the socket engine for DNSSEC queries and returns the AD flag' {
        $ctx = New-TestContext
        $ctx.Vantage = 'External'; $ctx.Resolvers = @('192.0.2.53')
        $r = Resolve-Record -Name 'example.net' -Type SOA -Context $ctx -DnssecOk
        Assert-Equal 'Wire' $r.Engine
        Assert-True $r.Authenticated
        Assert-True $r.Signed
    }
}
