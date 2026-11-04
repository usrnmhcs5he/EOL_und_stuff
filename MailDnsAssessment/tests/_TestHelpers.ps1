# Shared test setup. Dot-source from a BeforeAll block:
#   BeforeAll { . (Join-Path $PSScriptRoot '_TestHelpers.ps1') }
# Loads every function of the module without importing it (so tests can replace the
# DNS/HTTPS engine functions with fixture fakes), and defines
# assertion helpers that work the same in Pester 3.4 and Pester 5 (plain throw).

$ScriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'MailDnsAssessment.psm1'
$parseTokens = $null
$parseErrors = $null
$scriptAst = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$parseTokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw "Parse error in ${ScriptPath}: $($parseErrors[0].Message)" }
foreach ($functionAst in $scriptAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($functionAst.Extent.Text))
}

function Assert-Equal {
    param($Expected, $Actual, [string]$Message)
    if ($null -eq $Expected) { $ok = ($null -eq $Actual) }
    elseif ($Expected -is [string] -and $Actual -is [string]) { $ok = ($Expected -ceq $Actual) }
    else { $ok = ($Expected -eq $Actual) }
    if (-not $ok) { throw "Expected [$Expected] but got [$Actual]. $Message" }
}

function Assert-True {
    param($Condition, [string]$Message)
    if (-not $Condition) { throw "Assertion failed. $Message" }
}

function Assert-SetEqual {
    param([object[]]$Expected, [object[]]$Actual, [string]$Message)
    $e = (@($Expected | Sort-Object -Unique) -join ', ')
    $a = (@($Actual | Sort-Object -Unique) -join ', ')
    if ($e -cne $a) { throw "Expected set [$e] but got [$a]. $Message" }
}

function Assert-Contains {
    param([object[]]$Collection, $Item, [string]$Message)
    if (@($Collection) -notcontains $Item) { throw "Expected collection to contain [$Item]. $Message" }
}
