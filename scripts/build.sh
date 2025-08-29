#!/bin/bash

set -e

echo "[*] Building KittyLoader..."
echo

check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo "[!] $1 not found. Please install $2"
        exit 1
    fi
}

check_tool "x86_64-w64-mingw32-cmake" "mingw-w64"
check_tool "make" "make"
check_tool "cmake" "cmake"

mkdir -p build
cd build

echo "[*] Configuring project..."
x86_64-w64-mingw32-cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTS=${1:-OFF} \
    -DCMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++"

if [ $? -ne 0 ]; then
    echo "[!] CMake configuration failed"
    exit 1
fi

echo "[*] Building project..."
make -j$(nproc) KittyLoader
if [ $? -ne 0 ]; then
    echo "[!] Build failed"
    exit 1
fi

if [ "$1" = "--tests" ]; then
    echo "[*] Building tests..."
    make -j$(nproc) test_loader
    if [ $? -ne 0 ]; then
        echo "[!] Test build failed"
        exit 1
    fi
fi

echo
echo "[+] Build successful!"
echo "[+] Output: build/bin/KittyLoader.dll"

if [ -f "bin/test_loader.exe" ]; then
    echo "[+] Test executable: build/bin/test_loader.exe"
fi

cd ..