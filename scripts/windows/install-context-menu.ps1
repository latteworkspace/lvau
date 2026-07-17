[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BinaryPath,
    [string]$ContextScriptPath
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ContextScriptPath)) {
    $ContextScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'lvau-context.ps1'
}
$cli = (Resolve-Path -LiteralPath $BinaryPath).Path
$context = (Resolve-Path -LiteralPath $ContextScriptPath).Path

function Register-LvauMenu([string]$keyPath, [string]$label, [string]$mode, [string]$icon) {
    # Windows PowerShell 5.1 New-Item has no -LiteralPath parameter.
    # Escape the wildcard class key so * is treated literally.
    $providerKeyPath = $keyPath.Replace('*', '[*]')
    New-Item -Path $providerKeyPath -Force | Out-Null
    Set-ItemProperty -LiteralPath $keyPath -Name 'MUIVerb' -Value $label
    Set-ItemProperty -LiteralPath $keyPath -Name 'Icon' -Value $icon
    $commandKey = Join-Path $keyPath 'command'
    New-Item -Path $commandKey -Force | Out-Null
    $command = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Normal -File "{0}" -Mode {1} -CliPath "{2}" -LiteralPath "%1"' -f $context, $mode, $cli
    Set-ItemProperty -LiteralPath $commandKey -Name '(default)' -Value $command
}

Remove-Item -LiteralPath 'HKCU:\Software\Classes\*\shell\Lvau.Encrypt' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKCU:\Software\Classes\SystemFileAssociations\.lvau\shell\Lvau.Decrypt' -Recurse -Force -ErrorAction SilentlyContinue
Register-LvauMenu 'HKCU:\Software\Classes\*\shell\Lvau' 'Lvau' 'Auto' $cli
Write-Host 'Lvau context menu registered for the current user.'
