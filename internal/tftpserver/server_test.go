package tftpserver

import "testing"

func TestNewValidatesConfiguration(t *testing.T) {
	t.Parallel()
	for _, cfg := range []Config{
		{Address: ":69", Root: "tftp"},
		{Address: "0.0.0.0:69", Root: "tftp"},
		{Address: "[::1]:69", Root: "tftp"},
		{Address: "224.0.0.1:69", Root: "tftp"},
		{Address: "127.0.0.1:0"},
	} {
		if _, err := New(cfg, nil); err == nil {
			t.Fatalf("accepted invalid config %+v", cfg)
		}
	}
	if _, err := New(Config{Address: "127.0.0.1:0", Root: "tftp"}, nil); err != nil {
		t.Fatal(err)
	}
}
