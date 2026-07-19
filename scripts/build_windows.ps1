[CmdletBinding()]
param(
    [string]$Python = "python",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

& $Python -m pip install --upgrade pip
& $Python -m pip install -r requirements-build.txt

if (-not $SkipTests) {
    & $Python -m pip install -r requirements-dev.txt
    & $Python -m pytest -q
    & $Python -m ruff check .
    & $Python -m bandit -r system_info main.py -q
    & $Python main.py --check | Out-Null
}

Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
& $Python -m PyInstaller --clean --noconfirm VigilScope.spec

$ExePath = Join-Path $ProjectRoot "dist\VigilScope.exe"
if (-not (Test-Path $ExePath)) {
    throw "PyInstaller did not produce $ExePath"
}

$Process = Start-Process -FilePath $ExePath -ArgumentList "--check" -PassThru -Wait
if ($Process.ExitCode -ne 0) {
    throw "Packaged health check failed with exit code $($Process.ExitCode)"
}

$Hash = (Get-FileHash -Algorithm SHA256 $ExePath).Hash.ToLowerInvariant()
"$Hash  VigilScope.exe" | Set-Content -Encoding ascii "dist\VigilScope.exe.sha256"

Write-Host "Built: $ExePath"
Write-Host "SHA-256: $Hash"
