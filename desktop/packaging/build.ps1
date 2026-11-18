param(
    [string]$Python = "python",
    [string]$Compiler = "$(${env:ProgramFiles(x86)})\Inno Setup 6\ISCC.exe"
)
$ErrorActionPreference = "Stop"
if ([Environment]::OSVersion.Platform -ne "Win32NT") { throw "Build requires Windows." }
$project = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
Push-Location $project
try {
    & $Python -c "import struct; assert struct.calcsize('P') == 8"
    if ($LASTEXITCODE -ne 0) { throw "64-bit Python is required." }
    & $Python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Could not create an isolated environment." }
    $venv = Join-Path $project ".venv\Scripts\python.exe"
    & $venv -m pip install ".[gui,yara,build,test]"
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
    & $venv -m pytest -q
    if ($LASTEXITCODE -ne 0) { throw "Tests failed." }
    & $venv -m PyInstaller --noconfirm --clean --onefile --windowed --name PUSKESAU_SENTINEL_Advanced_Portable `
        --collect-data sentinel_inspector --version-file packaging/version.txt --icon src/sentinel_inspector/sentinel.ico packaging/entry.py
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
    if (!(Test-Path -LiteralPath $Compiler)) { throw "Inno Setup 6.3+ ISCC not found. Supply -Compiler." }
    & $Compiler packaging/sentinel.iss
    if ($LASTEXITCODE -ne 0) { throw "Inno Setup failed." }
    $release = Get-Item "dist/PUSKESAU_SENTINEL_Advanced_Portable.exe", "dist/PUSKESAU_SENTINEL_Advanced_Setup.exe"
    $manifest = foreach ($file in $release) {
        @{ name = $file.Name; size = $file.Length; sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant() }
    }
    @{ version = "1.1.0"; platform = "windows-x64"; files = @($manifest) } |
        ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 "dist/release-manifest.json"
    $manifest | ForEach-Object { "$($_.sha256)  $($_.name)" } | Set-Content -Encoding ascii "dist/SHA256SUMS"
} finally {
    Pop-Location
}
