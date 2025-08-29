@echo off
setlocal enabledelayedexpansion

echo [*] Building KittyLoader...
echo.

where cmake >nul 2>nul
if errorlevel 1 (
    echo [!] CMake not found. Please install CMake from https://cmake.org/
    exit /b 1
)

where ml64 >nul 2>nul
if errorlevel 1 (
    echo [!] MASM (ml64) not found. Please install Visual Studio Build Tools
    echo [!] Run: scripts\setup.ps1 to configure environment
    exit /b 1
)

if not exist build mkdir build
cd build

echo [*] Configuring project...
cmake .. -DCMAKE_BUILD_TYPE=Release -G "Visual Studio 17 2022" -A x64
if errorlevel 1 (
    echo [!] CMake configuration failed
    exit /b 1
)

echo [*] Building project...
cmake --build . --config Release --target KittyLoader -- /m
if errorlevel 1 (
    echo [!] Build failed
    exit /b 1
)

if "%1"=="--tests" (
    echo [*] Building tests...
    cmake --build . --config Release --target test_loader
    if errorlevel 1 (
        echo [!] Test build failed
        exit /b 1
    )
)

echo.
echo [+] Build successful!
echo [+] Output: build\bin\Release\KittyLoader.dll

if exist test_loader.exe (
    echo [+] Test executable: build\bin\Release\test_loader.exe
)

cd ..