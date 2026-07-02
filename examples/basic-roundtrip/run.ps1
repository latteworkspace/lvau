$ErrorActionPreference = "Stop"

$WorkDir = Join-Path ([System.IO.Path]::GetTempPath()) ("lvau-roundtrip-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $WorkDir | Out-Null

try {
    $Bin = if ($env:LVAU_CLI) { $env:LVAU_CLI } else { "lvau-cli" }

    $InputFile = Join-Path $WorkDir "sample.txt"
    $PasswordFile = Join-Path $WorkDir "password.txt"
    $EncryptedFile = Join-Path $WorkDir "sample.lvau"
    $DecryptedFile = Join-Path $WorkDir "sample.decrypted.txt"

    "Hello, Lvau! This file should survive encryption and decryption." | Set-Content -NoNewline -Path $InputFile
    "correct horse battery staple" | Set-Content -Path $PasswordFile

    & $Bin encrypt --in-file $InputFile --out-file $EncryptedFile --password-file $PasswordFile --profile fast
    & $Bin inspect --in-file $EncryptedFile
    & $Bin decrypt --in-file $EncryptedFile --out-file $DecryptedFile --password-file $PasswordFile

    Get-FileHash $InputFile -Algorithm SHA256
    Get-FileHash $DecryptedFile -Algorithm SHA256

    if ((Get-FileHash $InputFile -Algorithm SHA256).Hash -ne (Get-FileHash $DecryptedFile -Algorithm SHA256).Hash) {
        throw "Roundtrip hash mismatch."
    }

    "Roundtrip succeeded."
}
finally {
    Remove-Item -Recurse -Force -LiteralPath $WorkDir
}
