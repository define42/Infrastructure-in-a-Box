package ntpserver

import "testing"

func TestNew(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"127.0.0.1:0", "192.168.50.2:123"} {
		if _, err := New(Config{Address: address}, nil); err != nil {
			t.Errorf("New(%q): %v", address, err)
		}
	}
	for _, address := range []string{"", ":123", "0.0.0.0:123", "[::1]:123", "localhost:123", "224.0.0.1:123", "255.255.255.255:123"} {
		if _, err := New(Config{Address: address}, nil); err == nil {
			t.Errorf("accepted invalid listener %q", address)
		}
	}
}
