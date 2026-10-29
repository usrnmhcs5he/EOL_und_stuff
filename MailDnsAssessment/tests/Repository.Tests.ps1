# Repository conventions: matching version numbers, README rule table, ASCII sources, sample data.

Describe 'Repository conventions' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '_TestHelpers.ps1')
        $root = Split-Path -Parent $PSScriptRoot
        $scriptText = [System.IO.File]::ReadAllText((Join-Path $root 'Invoke-MailDnsAssessment.ps1'))
        $moduleText = [System.IO.File]::ReadAllText((Join-Path $root 'MailDnsAssessment.psm1'))
        $readme = [System.IO.File]::ReadAllText((Join-Path $root 'README.md'))
        function Get-TrailingVersion { param([string]$Text) $last = @($Text -split "`r?`n" | Where-Object { $_.Trim() })[-1]; if ($last -match '^# Version: (\d+)$') { [int]$Matches[1] } }
    }

    It 'keeps script, module and README versions in step' {
        $v = Get-TrailingVersion $scriptText
        Assert-True ($null -ne $v) 'script does not end with # Version: N'
        Assert-Equal $v (Get-TrailingVersion $moduleText) 'module # Version'
        Assert-True ($scriptText -match '(?m)^\$ScriptVersion = (\d+)\s*$') 'missing $ScriptVersion'
        Assert-Equal $v ([int]$Matches[1]) '$ScriptVersion'
        Assert-True ($moduleText -match '(?m)^\$script:ModuleVersion = (\d+)\s*$') 'missing $script:ModuleVersion'
        Assert-Equal $v ([int]$Matches[1]) '$script:ModuleVersion'
        Assert-True ($readme -match 'Current version: \*\*(\d+)\*\*') 'README has no current version'
        Assert-Equal $v ([int]$Matches[1]) 'README version'
        Assert-True ($scriptText -match ('(?m)^#\s+' + $v + '\s+\S')) "version history has no entry for $v"
    }

    It 'exposes comment-based help for the script and every parameter' {
        $help = Get-Help (Join-Path $root 'Invoke-MailDnsAssessment.ps1') -Full
        Assert-True ($help.Synopsis -match 'Read-only assessment') 'synopsis missing'
        foreach ($p in @('DomainList', 'Domain', 'Vantage', 'InternalResolver', 'ExternalResolver', 'DkimSelector', 'CheckMtaSts', 'CheckDane', 'CheckDnssec', 'OutputPath', 'Sanitize', 'TimeoutSeconds')) {
            $text = @($help.parameters.parameter | Where-Object { $_.name -eq $p } | ForEach-Object { $_.description } | ForEach-Object { $_.Text }) -join ' '
            Assert-True ($text.Length -gt 0) "no help for -$p"
        }
    }

    It 'documents every rule with its severity in the README' {
        foreach ($rule in (Get-RuleCatalog).Values) {
            $pattern = '\| `' + [regex]::Escape($rule.RuleId) + '` \| ' + $rule.Severity + ' \| '
            Assert-True ($readme -match $pattern) "README rule table: $($rule.RuleId) $($rule.Severity)"
        }
        $documented = @([regex]::Matches($readme, '\| `([A-Z]+-\d{3})` \|') | ForEach-Object { $_.Groups[1].Value })
        Assert-SetEqual @((Get-RuleCatalog).Keys) $documented 'README lists a rule the catalog does not have'
    }

    It 'keeps sources ASCII-only' {
        foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File -Include *.ps1, *.psm1)) {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            Assert-True (@($bytes | Where-Object { $_ -gt 127 }).Count -eq 0) "$($file.Name) contains non-ASCII bytes"
        }
    }

    It 'ships only reserved example domains in the sample list' {
        $lines = @(Get-Content -LiteralPath (Join-Path $root 'domains.sample.txt') | ForEach-Object { ($_ -split '#', 2)[0].Trim() } | Where-Object { $_ })
        Assert-True ($lines.Count -gt 0)
        foreach ($l in $lines) { Assert-True ($l -match '(^|\.)example\.(com|net|org)$') "non-example domain '$l'" }
    }

    It 'ignores the real domain list and the reports' {
        $ignore = [System.IO.File]::ReadAllText((Join-Path $root '.gitignore'))
        foreach ($p in @('domains.txt', 'output/*.json', 'output/*.csv', 'output/*.md')) { Assert-True ($ignore -match [regex]::Escape($p)) "missing $p" }
    }
}
