#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

# Preparation runs as the caller. Only run.py needs network administration.
assets="$PWD/.cache/e2e-qemu"
mkdir -p "$assets"
archive=alpine-netboot-3.23.3-x86_64.tar.gz
checksum=53fb5466f7612d4ff616bde0f637f0b8cd267d7e52aedc705220f487e431f150
if [[ ! -f "$assets/$archive" ]]; then
    curl --fail --location --retry 3 --max-time 300 \
        "https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/$archive" \
        -o "$assets/$archive.part"
    mv "$assets/$archive.part" "$assets/$archive"
fi
echo "$checksum  $assets/$archive" | sha256sum --check
tar -xzf "$assets/$archive" -C "$assets" boot/vmlinuz-virt boot/initramfs-virt
go build -race -o "$assets/infra-box" ./cmd/infra-box
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -tags=e2e_guest \
    -o "$assets/probe" ./tests/e2e-qemu/guest
