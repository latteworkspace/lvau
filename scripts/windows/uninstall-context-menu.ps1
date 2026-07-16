$ErrorActionPreference = 'Stop'
Remove-Item -LiteralPath 'HKCU:\Software\Classes\*\shell\Lvau.Encrypt' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKCU:\Software\Classes\SystemFileAssociations\.lvau\shell\Lvau.Decrypt' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKCU:\Software\Classes\*\shell\Lvau' -Recurse -Force -ErrorAction SilentlyContinue

# Remove legacy LatteVault entries by their displayed menu label.
$menuRoots = @(
    'HKCU:\Software\Classes\*\shell',
    'HKCU:\Software\Classes\SystemFileAssociations\.lvau\shell'
)
foreach ($root in $menuRoots) {
    Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | ForEach-Object {
        $item = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
        if ($item.MUIVerb -match '(?i)lattevault') {
            Remove-Item -LiteralPath $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Remove-Item -LiteralPath 'HKCU:\Software\Classes\*\shell\LatteVault.Encrypt' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKCU:\Software\Classes\*\shell\LatteVault.Decrypt' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath 'HKCU:\Software\Classes\SystemFileAssociations\.lvau\shell\LatteVault.Decrypt' -Recurse -Force -ErrorAction SilentlyContinue
Write-Host 'Lvau context menu removed.'
