//go:build integration && linux

package nfsserver

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// This opt-in test must run in a disposable mount AND network namespace with
// loopback only. The ordinary integration suite needs neither root nor mounts.
func TestNFSKernelMount(t *testing.T) {
	if os.Getenv("INFRA_BOX_NFS_KERNEL_TEST") != "1" {
		t.Skip("requires an isolated mount/network namespace and Linux NFS client")
	}
	selfMount, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	initMount, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	if selfMount == initMount {
		t.Fatal("kernel NFS test requires a disposable mount namespace")
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("kernel NFS test requires a network namespace containing only loopback")
	}
	listener, _, _, _, _ := loopbackServer(t)
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, share := range []string{"data", "software"} {
		t.Run(share, func(t *testing.T) {
			mount := t.TempDir()
			options := "addr=127.0.0.1,port=" + port + ",vers=4,minorversion=0,proto=tcp,sec=none,clientaddr=127.0.0.1,soft,timeo=10,retrans=1"
			if err := syscall.Mount("127.0.0.1:/"+share, mount, "nfs4", 0, options); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := syscall.Unmount(mount, syscall.MNT_DETACH); err != nil {
					t.Error(err)
				}
			})
			data, err := os.ReadFile(filepath.Join(mount, "hello"))
			if err != nil || string(data) != "hello world" {
				t.Fatalf("mounted read: %q %v", data, err)
			}
			err = os.WriteFile(filepath.Join(mount, "created"), []byte("kernel write"), 0644)
			if share == "software" {
				if err == nil {
					t.Fatal("kernel wrote to readonly share")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err = os.ReadFile(filepath.Join(mount, "created"))
			if err != nil || string(data) != "kernel write" {
				t.Fatalf("mounted write: %q %v", data, err)
			}
			if err := os.Rename(filepath.Join(mount, "created"), filepath.Join(mount, "renamed")); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(mount, "renamed")); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(mount, "dir"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filepath.Join(mount, "dir")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
