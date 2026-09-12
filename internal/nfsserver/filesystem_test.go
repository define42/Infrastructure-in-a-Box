package nfsserver

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func testFilesystem(t *testing.T) (*filesystem, string, string) {
	t.Helper()
	data, software := t.TempDir(), t.TempDir()
	for _, dir := range []string{data, software} {
		if err := os.WriteFile(filepath.Join(dir, "hello"), []byte("hello world"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	f, err := openFilesystem([]config.NFSShare{{Share: "data", Path: data}, {Share: "software", Path: software, ReadOnly: true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	return f, data, software
}

func TestFilesystemShares(t *testing.T) {
	t.Parallel()
	f, data, _ := testFilesystem(t)
	root, err := f.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	entries, err := root.Readdir(-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name() != "data" || entries[1].Name() != "software" {
		t.Fatalf("root entries: %v", entries)
	}
	opened, err := f.OpenFile("/data/new", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	if _, err := opened.Write([]byte("written")); err != nil {
		t.Fatal(err)
	}
	if err := opened.Sync(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(data, "new"))
	if err != nil || string(got) != "written" {
		t.Fatalf("write: %q %v", got, err)
	}
	if err := f.Rename("/data/new", "/software/new"); err == nil {
		t.Fatal("cross-share rename succeeded")
	}
}

func TestReadOnlyEveryMutation(t *testing.T) {
	t.Parallel()
	f, _, software := testFilesystem(t)
	opened, err := f.OpenFile("/software/hello", os.O_RDWR, 0644)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = opened.Close() }()
	content, err := io.ReadAll(opened)
	if err != nil || string(content) != "hello world" {
		t.Fatalf("read: %q %v", content, err)
	}
	checks := map[string]func() error{
		"write":    func() error { _, err := opened.Write([]byte("bad")); return err },
		"truncate": opened.Truncate,
		"create": func() error {
			file, err := f.OpenFile("/software/new", os.O_CREATE|os.O_RDWR, 0644)
			if file != nil {
				_ = file.Close()
			}
			return err
		},
		"open truncate": func() error {
			file, err := f.OpenFile("/software/hello", os.O_TRUNC|os.O_RDWR, 0644)
			if file != nil {
				_ = file.Close()
			}
			return err
		},
		"chmod":              func() error { return f.Chmod("/software/hello", 0777) },
		"chown":              func() error { return f.Chown("/software/hello", 1, 1) },
		"remove":             func() error { return f.Remove("/software/hello") },
		"mkdir":              func() error { return f.MkdirAll("/software/new", 0755) },
		"rename source":      func() error { return f.Rename("/software/hello", "/data/new") },
		"rename destination": func() error { return f.Rename("/data/hello", "/software/hello") },
		"link":               func() error { return f.Link("/data/hello", "/software/new") },
		"symlink":            func() error { return f.Symlink("/data/hello", "/software/new") },
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			if err := check(); err == nil {
				t.Fatal("mutation succeeded")
			}
		})
	}
	content, err = os.ReadFile(filepath.Join(software, "hello"))
	if err != nil || string(content) != "hello world" {
		t.Fatalf("changed readonly file: %q %v", content, err)
	}
	info, err := f.Stat("/software/hello")
	if err != nil || info.Mode().Perm()&0222 != 0 {
		t.Fatalf("writable readonly attrs: %v %v", info, err)
	}
}

func TestFilesystemContainmentAndHandles(t *testing.T) {
	t.Parallel()
	f, data, outside := testFilesystem(t)
	if err := os.Symlink(outside, filepath.Join(data, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"/data/../software/hello", "/unknown/hello", "/data/escape/hello", "/data/hello\x00"} {
		file, err := f.Open(name)
		if err == nil {
			_ = file.Close()
			t.Fatalf("opened forbidden path %q", name)
		}
	}
	info, err := f.Stat("/data/hello")
	if err != nil {
		t.Fatal(err)
	}
	handle, err := f.GetHandle(info)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range [][]byte{nil, {1}, make([]byte, 16), append(handle, 0)} {
		if _, err := f.ResolveHandle(h); err == nil {
			t.Fatalf("accepted bad handle %x", h)
		}
	}
	if err := f.Rename("/data/hello", "/data/moved"); err != nil {
		t.Fatal(err)
	}
	if name, err := f.ResolveHandle(handle); err != nil || name != "/data/moved" {
		t.Fatalf("renamed handle: %q %v", name, err)
	}
	if err := f.Remove("/data/moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "moved"), []byte("replacement"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ResolveHandle(handle); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale handle: %v", err)
	}
	if err := syscall.Mkfifo(filepath.Join(data, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := f.Open("/data/fifo"); err == nil {
		_ = file.Close()
		t.Fatal("opened FIFO")
	}
}

func TestFilesystemRejectsMissingAndAliasedRoots(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	for _, shares := range [][]config.NFSShare{
		{{Share: "missing", Path: filepath.Join(dir, "missing")}},
		{{Share: "data", Path: dir}, {Share: "readonly", Path: alias, ReadOnly: true}},
	} {
		if f, err := openFilesystem(shares); err == nil {
			_ = f.Close()
			t.Fatal("accepted invalid roots")
		}
	}
}
