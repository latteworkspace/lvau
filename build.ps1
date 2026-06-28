$ErrorActionPreference = "Stop"

Write-Host "Building Lvau with Hardware Acceleration (target-cpu=native)..."
$env:RUSTFLAGS="-C target-cpu=native"
cargo build --release

$outputDir = "release_binaries"
if (!(Test-Path -Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir | Out-Null
}

$targetDir = if ($env:CARGO_TARGET_DIR) { "$env:CARGO_TARGET_DIR/release" } else { "target/release" }

Write-Host "Copying CLI to $outputDir..."
Copy-Item "$targetDir/lvau-cli.exe" -Destination "$outputDir/lvau-cli.exe" -Force

Write-Host "Copying GUI to $outputDir..."
Copy-Item "$targetDir/lvau-gui.exe" -Destination "$outputDir/" -Force

Write-Host "Copying SFX Stub to $outputDir..."
Copy-Item "$targetDir/lvau-stub.exe" -Destination "$outputDir/" -Force

Write-Host "Build complete! Executables are located in the '$outputDir' folder."
