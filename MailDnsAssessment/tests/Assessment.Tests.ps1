# End-to-end run against fixture zones (no network): findings, summary, diff, reports, sanitisation.

Describe 'Invoke-Assessment with fixture zones' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_TestHelpers.ps1')
        . (Join-Path $PSScriptRoot 'Fixtures.ps1')
        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ('mda-test-' + [guid]::NewGuid().ToString('N'))
        $params = @{
            DomainName = @('example.com', 'example.net', 'example.org'); Vantage = 'Both'
            InternalResolver = @('10.0.0.99', '10.0.0.53'); ExternalResolver = @('192.0.2.53')
            CheckMtaSts = $true; CheckDane = $true; CheckDnssec = $true; TimeoutSeconds = 1; ScriptVersion = 'test'
        }
        $run = Invoke-Assessment @params -OutputPath (Join-Path $outDir 'plain') -WarningAction SilentlyContinue
        $sanitized = Invoke-Assessment @params -OutputPath (Join-Path $outDir 'sanitized') -Sanitize -WarningAction SilentlyContinue
        function Get-RuleSet { param($Result, [string]$Domain) @($Result.Results | Where-Object { $_.Domain -eq $Domain } | ForEach-Object { $_.Findings } | ForEach-Object { "$($_.RuleId)@$($_.Vantage)" }) }
        function Get-ReportText { param([string]$Folder) (Get-ChildItem -LiteralPath $Folder -File | ForEach-Object { [System.IO.File]::ReadAllText($_.FullName) }) -join "`n" }
    }

    It 'reports the expected findings for the mixed/legacy domain' {
        $expected = @(
            'MX-002@External', 'MX-004@Both', 'MX-007@Internal', 'MX-009@External',
            'SPF-009@Both', 'SPF-010@Both', 'SPF-012@Both', 'SPF-018@Both',
            'DKIM-004@Both', 'DKIM-005@Both',
            'DMARC-003@Both', 'DMARC-004@Both', 'DMARC-007@Both', 'DMARC-008@Both',
            'MTASTS-004@External', 'MTASTS-007@Both', 'MTASTS-011@Internal', 'TLSRPT-001@Both',
            'DANE-001@Both', 'DANE-003@External', 'DNSSEC-001@Both',
            'OTHER-001@Both', 'OTHER-002@Both', 'TXT-001@Both', 'TXT-002@Both', 'AUTOD-002@Internal',
            'VANTAGE-001@Both', 'VANTAGE-002@Both', 'VANTAGE-005@Both'
        )
        Assert-SetEqual $expected (Get-RuleSet $run 'example.com')
    }

    It 'reports only the expected findings for the clean domain' {
        Assert-SetEqual @('SPF-011@Both', 'DNSSEC-002@Internal', 'DNSSEC-004@Both', 'DANE-002@Internal') (Get-RuleSet $run 'example.net')
    }

    It 'reports a non-existent domain' {
        Assert-SetEqual @('DOMAIN-001@Both') (Get-RuleSet $run 'example.org')
    }

    It 'orders findings by severity' {
        $f = @($run.Results[0].Findings)
        Assert-Equal 'Critical' $f[0].Severity
        Assert-Equal 'MTASTS-004' $f[0].RuleId
    }

    It 'fills the summary' {
        $s = $run.Results[0].Summary
        Assert-Equal 'Mixed' $s.MxClass
        Assert-Equal 4 $s.SpfLookups
        Assert-Equal 1 $s.SpfVoidLookups
        Assert-Equal '~all' $s.SpfAll
        Assert-Equal '2048' $s.DkimSelector1
        Assert-Equal '1024' $s.DkimSelector2
        Assert-Equal 'none' $s.DmarcP
        Assert-Equal 50 $s.DmarcPct
        Assert-Equal 'enforce' $s.MtaSts
        Assert-Equal 'Partial' $s.Dane
        Assert-Equal 'Unsigned' $s.Dnssec
        $n = $run.Results[1].Summary
        Assert-Equal 'EOP-DANE' $n.MxClass
        Assert-Equal 2 $n.SpfLookups
        Assert-Equal 'Validated' $n.Dane
        Assert-Equal 'Validated' $n.Dnssec
        Assert-Equal '4096' $n.DkimSelector2
    }

    It 'expands SPF with attribution and an IP inventory' {
        $spf = $run.Results[0].Checks.External.Spf
        Assert-Contains @($spf.IpRanges | ForEach-Object { $_.Range }) '198.51.100.0/24'
        $nested = @($spf.Terms | Where-Object { $_.Mechanism -eq 'include' -and $_.Value -eq 'missing.example.net' })[0]
        Assert-Equal '_spf.example.net' $nested.Source
        Assert-Equal 1 $nested.Depth
        Assert-Equal 6 $spf.ProjectedLookupsWithEop
    }

    It 'records resolver and TTL per vantage' {
        $rows = @($run.Results[0].Records | Where-Object { $_.Query -eq 'example.com' -and $_.QueryType -eq 'MX' -and -not $_.DnssecOk })
        Assert-SetEqual @('10.0.0.53', '192.0.2.53') @($rows | ForEach-Object { $_.Resolver })
        Assert-True (@($rows | Where-Object { $_.TTL -eq 7200 }).Count -eq 3)
    }

    It 'lists the cross-vantage differences' {
        $diff = @($run.Results[0].VantageDiff)
        Assert-SetEqual @('example.com MX Differs', 'example.com SOA Differs', 'autodiscover.example.com CNAME MissingInternal') @($diff | ForEach-Object { "$($_.Name) $($_.Type) $($_.Result)" })
    }

    It 'writes JSON, CSV and Markdown' {
        $json = Get-Content -LiteralPath $run.Paths.Json -Raw | ConvertFrom-Json
        Assert-Equal 3 @($json.Domains).Count
        Assert-Equal 3 @(Import-Csv -LiteralPath $run.Paths.Csv).Count
        $md = Get-Content -LiteralPath $run.Paths.Markdown -Raw
        Assert-True ($md -match '## example\.com')
        Assert-True ($md -match 'Cross-vantage diff')
    }

    It 'keeps the findings identical when sanitising' {
        foreach ($d in @('example.com', 'example.net', 'example.org')) {
            $plain = @($run.Results | Where-Object { $_.Domain -eq $d })[0]
            $i = [array]::IndexOf(@($run.Results | ForEach-Object { $_.Domain }), $d)
            Assert-SetEqual (Get-RuleSet $run $d) @($sanitized.Results[$i].Findings | ForEach-Object { "$($_.RuleId)@$($_.Vantage)" })
            Assert-Equal $plain.Findings.Count $sanitized.Results[$i].Findings.Count
        }
    }

    It 'leaves no input domain, tenant name, address or key in sanitised output' {
        $text = Get-ReportText (Join-Path $outDir 'sanitized')
        foreach ($s in @('example.com', 'example.net', 'example.org', 'example-com', 'example-net', 'tenant.', '203.0.113.5', '10.1.2.3', '10.0.0.53', 'ms12345678', $FixtureKeys.Spki2048.Substring(0, 30))) {
            Assert-True ($text.IndexOf($s, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) "found '$s'"
        }
        $json = Get-Content -LiteralPath $sanitized.Paths.Json -Raw | ConvertFrom-Json
        Assert-SetEqual @('domain-01', 'domain-02', 'domain-03') @($json.Domains | ForEach-Object { $_.Domain })
        Assert-True ((Get-Content -LiteralPath $sanitized.Paths.Markdown -Raw) -match '(?m)^## domain-02$')
        foreach ($s in @('domain-01', 'domain-02', 'mx-01', '203.0.113.0/24', '_25._tcp.mx-02.domain-02', 'spf.protection.outlook.com', 'mail.protection.outlook.com', 'tenant-01.onmicrosoft.com', '[key]')) {
            Assert-True ($text.IndexOf($s, [System.StringComparison]::Ordinal) -ge 0) "missing '$s'"
        }
    }

    It 'leaves rule titles and recommendations intact when sanitising' {
        $map = New-SanitizeMap -Domain @('example.com')
        foreach ($rule in (Get-RuleCatalog).Values) {
            Assert-Equal $rule.Title (ConvertTo-SanitizedString -Text $rule.Title -Map $map)
            Assert-Equal $rule.Recommendation (ConvertTo-SanitizedString -Text $rule.Recommendation -Map $map)
        }
    }

    It 'pseudonymises host names consistently' {
        $map = New-SanitizeMap -Domain @('example.com', 'example.net') -MxHost @('example-com.mail.protection.outlook.com', 'mail.example.com')
        Assert-Equal 'mx-01.mail.protection.outlook.com' (Get-SanitizedHostName 'example-com.mail.protection.outlook.com' $map)
        Assert-Equal 'mx-02.domain-01' (Get-SanitizedHostName 'mail.example.com' $map)
        Assert-Equal 'mx-02.domain-01' (Get-SanitizedHostName 'MAIL.example.com.' $map)
        Assert-Equal 'selector1._domainkey.domain-01' (Get-SanitizedHostName 'selector1._domainkey.example.com' $map)
        Assert-Equal 'domain-01._report._dmarc.domain-02' (Get-SanitizedHostName 'example.com._report._dmarc.example.net' $map)
        Assert-Equal 'host-01.o-v1.mx.microsoft' (Get-SanitizedHostName 'example-net.o-v1.mx.microsoft' $map)
        Assert-Equal 'host-02' (Get-SanitizedHostName 'mx1.gateway.example' $map)
        Assert-Equal '_25._tcp.mx-01.mail.protection.outlook.com' (Get-SanitizedHostName '_25._tcp.example-com.mail.protection.outlook.com' $map)
        Assert-Equal '_dmarc.domain-02' (Get-SanitizedHostName '_dmarc.example.net' $map)
        Assert-Equal '_spf.google.com' (Get-SanitizedHostName '_spf.google.com' $map)
        Assert-Equal '198.51.100.0/24' (ConvertTo-MaskedIp -Address '198.51.100.77' -Map $map)
        Assert-Equal '2001:db8:1::/48' (ConvertTo-MaskedIp -Address '2001:db8:1:2::5' -Map $map)
        Assert-Equal '40.92.0.0/15' (ConvertTo-MaskedIp -Address '40.92.0.0' -Prefix '15' -Map $map)
        Assert-Equal '1.1.1.1' (ConvertTo-MaskedIp -Address '1.1.1.1' -Map $map)
    }

    It 'cleans up' {
        Remove-Item -LiteralPath $outDir -Recurse -Force
        Assert-True (-not (Test-Path -LiteralPath $outDir))
    }
}
