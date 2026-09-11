package dhcpserver

import (
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestClientHostname(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"option12", nil, "fallback"},
		{"fqdn ascii", append([]byte{0, 0, 0}, "laptop.home.arpa"...), "laptop.home.arpa"},
		{"fqdn wire", []byte{4, 0, 0, 6, 'l', 'a', 'p', 't', 'o', 'p', 0}, "laptop"},
		{"fqdn partial", []byte{4, 0, 0, 3, 'p', 'c', '1'}, "pc1"},
		{"no registration", []byte{8, 0, 0}, "\x00"},
		{"compression rejected", []byte{4, 0, 0, 0xc0, 0}, "\x00"},
		{"truncated", []byte{4, 0, 0, 9, 'a'}, "\x00"},
		{"trailing junk", []byte{4, 0, 0, 0, 42}, "\x00"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := packet(t, dhcpv4.MessageTypeRequest, 1, dhcpv4.WithOption(dhcpv4.OptHostName("fallback")))
			if tt.raw != nil {
				p.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionFQDN, tt.raw))
			}
			if got := clientHostname(p); got != tt.want {
				t.Fatalf("hostname = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHandleFQDN(t *testing.T) {
	t.Parallel()
	s, manager := testServer(t, "")
	request := packet(t, dhcpv4.MessageTypeRequest, 1,
		dhcpv4.WithGeneric(dhcpv4.OptionRequestedIPAddress, []byte{192, 168, 50, 100}),
		dhcpv4.WithGeneric(dhcpv4.OptionFQDN, []byte{4, 0, 0, 3, 'p', 'c', '1', 0}),
	)
	ack := handle(t, s, request, dhcpv4.MessageTypeAck)
	if _, ok := manager.LookupName("pc1.home.arpa."); !ok {
		t.Fatal("FQDN did not register")
	}
	if raw := ack.Options.Get(dhcpv4.OptionFQDN); len(raw) < 4 || raw[0] != 7 {
		t.Fatalf("FQDN reply = %v, want server registration with override and wire encoding", raw)
	}
	request.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionFQDN, []byte{8, 0, 0}))
	ack = handle(t, s, request, dhcpv4.MessageTypeAck)
	if _, ok := manager.LookupName("pc1.home.arpa."); ok {
		t.Fatal("N flag did not remove registration")
	}
	if raw := ack.Options.Get(dhcpv4.OptionFQDN); raw[0] != 8 {
		t.Fatalf("FQDN N response = %v", raw)
	}
}
