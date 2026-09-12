#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: ./build-ipxe.sh [--help]

Download iPXE and build BIOS and x64 UEFI loaders with our DHCP-based bootstrap.
Outputs are saved to ipxe/ beside this script for embedding in the application:
  pxelinux.0         BIOS iPXE loader (undionly.kpxe)
  bootx64.efi        x64 UEFI iPXE loader (unsigned)
  bootstrap.ipxe    Embedded startup script
  ipxe-revision.txt  Source commit used for this build
  COPYING*          Upstream license notices

Environment:
  IPXE_REF   Upstream branch, tag, or commit to build (default: master)
  IPXE_JOBS  Number of parallel build jobs (default: 4)

Requires a Linux x86 build environment, Git, GCC, binutils, Make, Perl,
xz/liblzma development files, and mtools. On Debian/Ubuntu:
  sudo apt-get install git build-essential perl liblzma-dev xz-utils mtools
EOF
}

if [[ $# -eq 1 && ( "$1" == -h || "$1" == --help ) ]]; then
    usage
    exit 0
fi
if [[ $# -ne 0 ]]; then
    usage >&2
    exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output_dir="$script_dir/ipxe"
build_jobs="${IPXE_JOBS:-4}"
ipxe_ref="${IPXE_REF:-master}"
if [[ ! "$build_jobs" =~ ^[1-9][0-9]*$ ]]; then
    echo "IPXE_JOBS must be a positive integer" >&2
    exit 2
fi

for tool in git gcc ld objcopy make perl xz mformat; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing build tool: $tool. See ./build-ipxe.sh --help for dependencies." >&2
        exit 1
    fi
done
if ! printf '#include <lzma.h>\nint main(void) { return lzma_version_number() == 0; }\n' |
    gcc -x c - -o /dev/null -llzma >/dev/null 2>&1; then
    echo "Missing usable liblzma development files; install liblzma-dev (Debian/Ubuntu)." >&2
    exit 1
fi

mkdir -p -- "$output_dir"
if [[ ! -w "$output_dir" || ! -x "$output_dir" ]]; then
    echo "Output directory is not writable: $output_dir" >&2
    exit 1
fi

build_dir="$(mktemp -d "${TMPDIR:-/tmp}/infra-box-ipxe.XXXXXX")"
trap 'rm -r -- "$build_dir" </dev/null' EXIT

git init --quiet "$build_dir"
git -C "$build_dir" fetch --depth=1 -- https://github.com/ipxe/ipxe.git "$ipxe_ref"
git -C "$build_dir" checkout --quiet --detach FETCH_HEAD
git -C "$build_dir" rev-parse HEAD > "$build_dir/ipxe-revision.txt"

# Keep iPXE's setting expansion literal; Bash must not expand ${next-server}.
cat > "$build_dir/src/bootstrap.ipxe" <<'EOF'
#!ipxe
dhcp
chain http://${next-server}/boot/boot.ipxe
EOF

# An inherited DEBUG value is interpreted by iPXE as a list of source filenames.
make -C "$build_dir/src" -j "$build_jobs" \
    bin/undionly.kpxe bin-x86_64-efi/ipxe.efi EMBED=bootstrap.ipxe DEBUG=
test -s "$build_dir/src/bin/undionly.kpxe"
test -s "$build_dir/src/bin-x86_64-efi/ipxe.efi"

install -m 0644 -- "$build_dir/src/bin/undionly.kpxe" "$output_dir/pxelinux.0"
install -m 0644 -- "$build_dir/src/bin-x86_64-efi/ipxe.efi" "$output_dir/bootx64.efi"
install -m 0644 -- "$build_dir/src/bootstrap.ipxe" "$build_dir/ipxe-revision.txt" "$output_dir/"
install -m 0644 -- "$build_dir"/COPYING* "$output_dir/"

printf '\nBuilt iPXE loaders in %s\n' "$output_dir"
printf 'Run make build and restart the application to use these built-in TFTP loaders.\n'
printf 'Place your main boot.ipxe script in tftp_root for HTTP access at /boot/boot.ipxe.\n'
