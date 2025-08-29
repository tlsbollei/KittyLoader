Write-Host "[*] Setting up KittyLoader build environment..." -ForegroundColor Yellow

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($vsPath) {
        $vcVarsPath = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $vcVarsPath) {
            Write-Host "[+] Found Visual Studio at: $vsPath" -ForegroundColor Green
            Write-Host "[+] Run the following command to setup environment:" -ForegroundColor Yellow
            Write-Host "    & `"$vcVarsPath`"" -ForegroundColor White
        }
    }
} else {
    Write-Host "[!] Visual Studio not found. Please install Visual Studio 2022" -ForegroundColor Red
}

if (Get-Command cmake -ErrorAction SilentlyContinue) {
    $cmakeVersion = cmake --version | Select-Object -First 1
    Write-Host "[+] CMake found: $cmakeVersion" -ForegroundColor Green
} else {
    Write-Host "[!] CMake not found. Please install from https://cmake.org/" -ForegroundColor Red
}

if (Get-Command ml64 -ErrorAction SilentlyContinue) {
    Write-Host "[+] MASM (ml64) found" -ForegroundColor Green
} else {
    Write-Host "[!] MASM not found. Please install Visual Studio Build Tools" -ForegroundColor Red
}

Write-Host "[+] Setup complete. Run 'scripts\build.bat' to compile." -ForegroundColor Green