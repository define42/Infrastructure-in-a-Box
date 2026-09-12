package tftpserver

import "testing"

func TestNewValidatesConfiguration(t *testing.T) {
	t.Parallel()
	for _, address := range []string{":69", "0.0.0.0:69", "[::1]:69", "224.0.0.1:69"} {
		t.Run(address, func(t *testing.T) {
			if _, err := New(Config{Address: address}, nil); err == nil {
				t.Fatalf("accepted invalid address %q", address)
			}
		})
	}
	if _, err := New(Config{Address: "127.0.0.1:0"}, nil); err != nil {
		t.Fatal(err)
	}
}
