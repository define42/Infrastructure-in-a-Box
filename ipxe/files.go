// Package ipxe contains the built-in BIOS and x64 UEFI network bootloaders.
package ipxe

import (
	"embed"
	"io/fs"
)

// Name the two loaders explicitly so source files, bootstrap scripts, and
// build metadata in this directory can never be exposed by TFTP.
//
//go:embed pxelinux.0 bootx64.efi
var loaders embed.FS

// Files returns the read-only bootloaders compiled into the application.
// Regenerate the assets with build-ipxe.sh before rebuilding the application.
func Files() fs.FS { return loaders }
