package ipxe

import (
	"errors"
	"io/fs"
	"slices"
	"testing"
)

func TestOnlyBootloadersAreEmbedded(t *testing.T) {
	t.Parallel()
	files := Files()
	entries, err := fs.ReadDir(files, ".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			t.Errorf("%s is not a nonempty bootloader", entry.Name())
		}
	}
	if want := []string{"bootx64.efi", "pxelinux.0"}; !slices.Equal(names, want) {
		t.Fatalf("embedded files = %v, want %v", names, want)
	}
	for _, name := range []string{"boot.ipxe", "bootstrap.ipxe", "ipxe-revision.txt", "COPYING", "files.go"} {
		if _, err := fs.ReadFile(files, name); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s: error = %v, want file not found", name, err)
		}
	}
}
