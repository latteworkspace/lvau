[CmdletBinding()]
param(
    [ValidateSet('Auto', 'Encrypt', 'Decrypt')][string]$Mode = 'Auto',
    [Parameter(Mandatory = $true)][string]$CliPath,
    [Parameter(Mandatory = $true)][string]$LiteralPath
)

$ErrorActionPreference = 'Stop'
$cli = (Resolve-Path -LiteralPath $CliPath).Path
$inputPath = (Resolve-Path -LiteralPath $LiteralPath).Path

if ($Mode -eq 'Auto') {
    if ($inputPath.EndsWith('.lvau', [System.StringComparison]::OrdinalIgnoreCase)) {
        $Mode = 'Decrypt'
    } else {
        $Mode = 'Encrypt'
    }
}

if ($Mode -eq 'Encrypt') {
    $outputPath = "$inputPath.lvau"
} else {
    if (-not $inputPath.EndsWith('.lvau', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Only .lvau files can be decrypted.'
    }
    $outputPath = $inputPath.Substring(0, $inputPath.Length - 5)
}

if (Test-Path -LiteralPath $outputPath) {
    throw "Output already exists; refusing to overwrite: $outputPath"
}

$arguments = @(
    $Mode.ToLowerInvariant(), '--in-file', $inputPath,
    '--out-file', $outputPath, '--password'
)
& $cli @arguments
if ($LASTEXITCODE -ne 0) {
    throw "lvau-cli exited with code $LASTEXITCODE."
}

Write-Host "Completed: $outputPath"
Read-Host 'Press Enter to close' | Out-Null
