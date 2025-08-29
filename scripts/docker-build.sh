#!/bin/bash
set -e

TAG="kittyloader-builder"

echo "[*] Building KittyLoader in Docker..."
echo

docker build -f docker/Dockerfile.windows -t $TAG .

docker run --rm -v $(pwd):/build $TAG

echo
echo "[+] Docker build completed, output files are in build/bin/"
