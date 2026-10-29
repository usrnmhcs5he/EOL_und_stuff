# Unit tests for the record parsers. Fixed input strings only, no network.

Describe 'ConvertFrom-SpfRecord' {
    BeforeAll { . (Join-Path $PSScriptRoot '_TestHelpers.ps1') }

    It 'parses mechanisms, qualifiers and modifiers' {
        $r = ConvertFrom-SpfRecord 'v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:example.net/24 include:_spf.example.com ~all redirect=example.net'
        Assert-True $r.Valid ($r.Errors -join '; ')
        Assert-Equal 7 $r.Terms.Count
        Assert-Equal 'ip4' $r.Terms[0].Name
        Assert-Equal '192.0.2.0/24' $r.Terms[0].Value
        Assert-Equal '2001:db8::/32' $r.Terms[1].Value
        Assert-Equal 'example.net' $r.Terms[3].Value
        Assert-Equal '24' $r.Terms[3].Cidr
        Assert-Equal '~' $r.Terms[5].Qualifier
        Assert-Equal 'Modifier' $r.Terms[6].Kind
        Assert-Equal 'redirect' $r.Terms[6].Name
    }

    It 'flags DNS-querying terms' {
        $r = ConvertFrom-SpfRecord 'v=spf1 include:a.example.com a mx ptr exists:x.example.com ip4:192.0.2.1 -all'
        Assert-Equal 5 @($r.Terms | Where-Object { $_.Lookup }).Count
    }

    It 'defaults the qualifier to +' {
        $r = ConvertFrom-SpfRecord 'v=spf1 all'
        Assert-Equal '+' $r.Terms[0].Qualifier
    }

    It 'reports unknown mechanisms and bad addresses as errors' {
        $r = ConvertFrom-SpfRecord 'v=spf1 ip4:300.1.1.1 foo:bar ip6:192.0.2.1 -all'
        Assert-True (-not $r.Valid)
        Assert-Equal 3 $r.Errors.Count ($r.Errors -join '; ')
    }

    It 'rejects a record without the version tag' {
        Assert-True (-not (ConvertFrom-SpfRecord 'spf1 -all').Valid)
    }

    It 'marks macros' {
        $r = ConvertFrom-SpfRecord 'v=spf1 exists:%{i}._spf.example.com -all'
        Assert-True $r.Terms[0].HasMacro
    }
}

Describe 'ConvertFrom-DmarcRecord' {
    BeforeAll { . (Join-Path $PSScriptRoot '_TestHelpers.ps1') }

    It 'parses all tags' {
        $d = ConvertFrom-DmarcRecord 'v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:dmarc@example.com,mailto:agg@example.net!10m; ruf=mailto:f@example.com; adkim=s; aspf=r; fo=1; rf=afrf; ri=86400'
        Assert-True $d.Valid ($d.Errors -join '; ')
        Assert-Equal 'quarantine' $d.P
        Assert-Equal 'reject' $d.Sp
        Assert-Equal 50 $d.Pct
        Assert-Equal 2 $d.Rua.Count
        Assert-Equal 'example.net' $d.Rua[1].Domain
        Assert-Equal 1 $d.Ruf.Count
        Assert-Equal 's' $d.Adkim
        Assert-Equal '1' $d.Fo
        Assert-Equal '86400' $d.Ri
    }

    It 'defaults pct to 100 and alignment to relaxed' {
        $d = ConvertFrom-DmarcRecord 'v=DMARC1; p=none'
        Assert-Equal 100 $d.Pct
        Assert-Equal 'r' $d.Adkim
        Assert-Equal 0 $d.Rua.Count
    }

    It 'reports syntax errors' {
        $d = ConvertFrom-DmarcRecord 'p=reject; v=DMARC1; pct=150; rua=https://example.com'
        Assert-True (-not $d.Valid)
        Assert-Equal 3 $d.Errors.Count ($d.Errors -join '; ')
    }

    It 'reports a missing policy' {
        Assert-True (-not (ConvertFrom-DmarcRecord 'v=DMARC1; rua=mailto:d@example.com').Valid)
    }
}

Describe 'ConvertFrom-TagValueRecord' {
    BeforeAll { . (Join-Path $PSScriptRoot '_TestHelpers.ps1') }

    It 'lower-cases keys, keeps values and reports duplicates' {
        $t = ConvertFrom-TagValueRecord 'V=STSv1; ID=20260101; id=2'
        Assert-Equal 'STSv1' $t.Tags['v']
        Assert-Equal '20260101' $t.Tags['id']
        Assert-Equal 1 $t.Errors.Count
    }
}

Describe 'ConvertFrom-MtaStsPolicy' {
    BeforeAll { . (Join-Path $PSScriptRoot '_TestHelpers.ps1') }

    It 'parses a valid policy with CRLF line endings' {
        $p = ConvertFrom-MtaStsPolicy "version: STSv1`r`nmode: enforce`r`nmx: *.mail.protection.outlook.com`r`nmx: mx1.example.com`r`nmax_age: 604800`r`n"
        Assert-Equal 0 $p.Errors.Count ($p.Errors -join '; ')
        Assert-Equal 'enforce' $p.Mode
        Assert-Equal 604800 $p.MaxAge
        Assert-Equal 2 $p.Mx.Count
    }

    It 'reports missing and invalid fields' {
        $p = ConvertFrom-MtaStsPolicy "version: STSv2`nmode: strict`n"
        Assert-SetEqual @('version must be STSv1', "Invalid mode 'strict'", 'max_age missing', 'No mx lines') $p.Errors
    }

    It 'accepts mode none without mx lines' {
        $p = ConvertFrom-MtaStsPolicy "version: STSv1`nmode: none`nmax_age: 86400"
        Assert-Equal 0 $p.Errors.Count ($p.Errors -join '; ')
    }
}

Describe 'Test-HostPattern' {
    BeforeAll { . (Join-Path $PSScriptRoot '_TestHelpers.ps1') }

    It 'matches a wildcard against exactly one label' {
        Assert-True (Test-HostPattern '*.mail.protection.outlook.com' 'example-com.mail.protection.outlook.com')
        Assert-True (-not (Test-HostPattern '*.example.com' 'a.b.example.com'))
        Assert-True (-not (Test-HostPattern '*.example.com' 'example.com'))
    }

    It 'matches exact names case-insensitively and ignores a trailing dot' {
        Assert-True (Test-HostPattern 'MX1.example.com' 'mx1.example.com.')
        Assert-True (-not (Test-HostPattern 'mx1.example.com' 'mx2.example.com'))
    }
}

Describe 'Classifiers' {
    BeforeAll { . (Join-Path $PSScriptRoot '_TestHelpers.ps1') }

    It 'classifies MX hosts' {
        Assert-Equal 'EOP' (Get-MxHostClass 'example-com.mail.protection.outlook.com')
        Assert-Equal 'EOP-DANE' (Get-MxHostClass 'example-com.o-v1.mx.microsoft')
        Assert-Equal 'OnPremises' (Get-MxHostClass -HostName 'mail.example.com' -ScopeDomain @('example.com'))
        Assert-Equal 'Other' (Get-MxHostClass -HostName 'mx1.gateway.example.net' -ScopeDomain @('example.com'))
    }

    It 'classifies DKIM CNAME targets' {
        Assert-Equal 'EOP' (Get-DkimCnameClass 'selector1-example-com._domainkey.tenant.onmicrosoft.com')
        Assert-Equal 'EOP' (Get-DkimCnameClass 'selector2-example-com01b._domainkey.tenant.k-v1.dkim.mail.microsoft')
        Assert-Equal 'Other' (Get-DkimCnameClass 'selector1.dkim.example.net')
    }

    It 'classifies apex TXT records' {
        Assert-Equal 'SPF' (Get-TxtClassification 'v=spf1 -all')
        Assert-Equal 'Microsoft 365 verification' (Get-TxtClassification 'MS=ms12345678')
        Assert-Equal 'Google verification' (Get-TxtClassification 'google-site-verification=abc')
        Assert-Equal 'Verification token' (Get-TxtClassification 'example-domain-verification=abc')
        Assert-Equal 'DMARC (misplaced)' (Get-TxtClassification 'v=DMARC1; p=none')
        Assert-Equal 'Other' (Get-TxtClassification 'some text')
    }
}
