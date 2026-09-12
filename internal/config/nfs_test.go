package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestNFSConfiguration(t *testing.T) {
	t.Parallel()
	path := writeConfig(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:strings.LastIndex(string(data), "}")], []byte(`,"nfs":[{"share":"data","path":"/var/data","read_only":false},{"share":"software","path":"/srv/software","read_only":true}]}`)...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NFSAddress != "192.168.50.2:2049" || len(cfg.NFS) != 2 || cfg.NFS[0].ReadOnly || !cfg.NFS[1].ReadOnly || cfg.NFS[1].Path != "/srv/software" {
		t.Fatalf("unexpected NFS configuration: %+v", cfg)
	}
}

func TestNFSInvalidConfiguration(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		`null`, `{}`, `[null]`, `[{}]`,
		`[{"share":"x","share":"y","path":"/srv/x"}]`,
		`[{"share":"x","path":"/srv/x","unknown":true}]`,
		`[{"share":"x","path":"/srv/x","read_only":null}]`,
		`[{"share":"x","path":"/srv/x","read_only":"false"}]`,
		`[{"share":"../x","path":"/srv/x"}]`,
		`[{"share":"x/y","path":"/srv/x"}]`,
		`[{"share":"x","path":"relative"}]`,
		`[{"share":"x","path":"/srv/x"},{"share":"x","path":"/srv/y"}]`,
		`[{"share":"x","path":"/srv/x"},{"share":"y","path":"/srv/x/sub"}]`,
		`[{"share":"x","path":"/"}]`,
	} {
		t.Run(value, func(t *testing.T) {
			path := writeConfig(t)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data[:strings.LastIndex(string(data), "}")], []byte(`,"nfs":`+value+`}`)...)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := config.Load(path); err == nil {
				t.Fatal("accepted invalid NFS configuration")
			}
		})
	}
}

func TestNFSProtectsPrivateState(t *testing.T) {
	t.Parallel()
	for _, target := range []string{"pki", "pki/nested", "."} {
		t.Run(target, func(t *testing.T) {
			path := writeConfig(t)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			shares, err := json.Marshal([]config.NFSShare{{Share: "private", Path: filepath.Join(filepath.Dir(path), target)}})
			if err != nil {
				t.Fatal(err)
			}
			data = append(data[:strings.LastIndex(string(data), "}")], []byte(`,"nfs":`+string(shares)+`}`)...)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := config.Load(path); err == nil {
				t.Fatal("accepted export of private state")
			}
		})
	}
}

func TestNFSRejectsPrivateStateSymlinkAlias(t *testing.T) {
	t.Parallel()
	path := writeConfig(t)
	private := filepath.Join(filepath.Dir(path), "pki")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "public")
	if err := os.Symlink(private, alias); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := json.Marshal([]config.NFSShare{{Share: "alias", Path: alias}})
	if err != nil {
		t.Fatal(err)
	}
	data = append(data[:strings.LastIndex(string(data), "}")], []byte(`,"nfs":`+string(shares)+`}`)...)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err == nil {
		t.Fatal("exported CA through symlink alias")
	}
}
