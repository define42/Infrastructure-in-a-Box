# Infrastructure-in-a-Box

A Go DHCPv4 server with a built-in DNS server. Clients receive an IPv4 lease and
the server's DNS address; their DHCP hostnames become local A and PTR records.
DHCP packet handling uses `github.com/insomniacslk/dhcp/dhcpv4`, and DNS uses
`github.com/miekg/dns`.

## Build and run

Use the Go version declared in `go.mod` or newer:

```sh
go build -o bin/infra-box ./cmd/infra-box
```

Configure a static IPv4 address on the interface before starting the server. For
example, with `192.168.50.2/24` already assigned to `eth0`, an existing router at
`192.168.50.1`, and addresses `.100` through `.200` available for DHCP:

```sh
sudo ./bin/infra-box \
  -interface eth0 \
  -server-ip 192.168.50.2 \
  -subnet 192.168.50.0/24 \
  -pool-start 192.168.50.100 \
  -pool-end 192.168.50.200 \
  -router 192.168.50.1 \
  -domain home.arpa \
  -lease-file /var/lib/infra-box/leases.json
```

Create the lease file's parent directory before running that example:
`sudo install -d -m 0750 /var/lib/infra-box`. Binding the default ports normally
requires root or suitable operating-system capabilities. Permit client traffic
to UDP port 67 and UDP/TCP port 53. Only run one DHCP server for this pool on the
network, and keep statically assigned addresses outside the pool.

The `-router` flag advertises an existing default gateway; the application does
not configure interfaces, enable routing, or provide NAT. Omit it if clients
should not receive a default gateway. The server address and optional router must
be usable addresses in the subnet, outside the DHCP pool.

A client announcing hostname `laptop` gets a record such as
`laptop.home.arpa. A 192.168.50.100`. After it acquires a lease, verify forward and
reverse DNS using its actual assigned address:

```sh
dig @192.168.50.2 laptop.home.arpa A
dig @192.168.50.2 -x 192.168.50.100
dig +tcp @192.168.50.2 laptop.home.arpa A
```

Clients must supply a hostname through DHCP to receive a DNS name. The server
uses Client FQDN option 81 when present, otherwise Host Name option 12, and honors
option 81's request to skip DNS registration. The local domain is advertised in
domain option 15 and search-list option 119 so clients can resolve short names.
`ns.home.arpa` identifies the built-in DNS server. The default domain,
[`home.arpa`](https://www.rfc-editor.org/rfc/rfc8375.html), is reserved for home
networks; avoid `.local`, which is reserved for
[multicast DNS](https://www.rfc-editor.org/rfc/rfc6762.html).

## Configuration

Run `./bin/infra-box -h` for command-line help. Configuration uses flags;
there is no configuration file or environment-variable layer.

| Flag | Default | Meaning |
| --- | --- | --- |
| `-interface` | required | Interface serving DHCP. |
| `-server-ip` | required | Static IPv4 address of this server, also advertised as the DNS server. |
| `-subnet` | required | Canonical IPv4 CIDR subnet, such as `192.168.50.0/24`. |
| `-pool-start` | required | First address in the DHCP pool. |
| `-pool-end` | required | Last address in the DHCP pool, inclusive. |
| `-router` | empty | Existing default gateway to advertise. |
| `-domain` | `home.arpa` | Domain for DHCP hostnames. |
| `-lease-duration` | `12h` | Lease lifetime, in whole seconds, at least `1m`. |
| `-lease-file` | `leases.json` | Persisted lease state; use `-lease-file ''` for memory only. |
| `-dhcp-listen` | `:67` | DHCP UDP listener. |
| `-dns-listen` | `<server-ip>:53` | DNS UDP and TCP listener. |
| `-upstream` | empty | Optional numeric IPv4 address and port for external DNS, such as `1.1.1.1:53`. |
| `-dns-ttl` | `1m` | Maximum TTL for DNS records, in whole seconds, at least `1s`. |

Both listeners accept `:port`, `0.0.0.0:port`, or `<server-ip>:port`. Alternate
ports support development, but normal DHCP clients expect DHCP port 67 and DNS
port 53; DHCP cannot advertise an alternate DNS port. Hostname-based upstream
addresses are rejected to avoid depending on DNS during startup. An upstream
must not point back to the DNS listener.

By default, DNS serves local names only. To resolve public names as well, add
`-upstream 1.1.1.1:53` or the address of your existing resolver. Local names are
answered from lease state and never forwarded. Restrict access to the DNS ports
to the network you intend to serve, particularly when forwarding is enabled.

## Lease and DNS behavior

- A DHCP offer temporarily reserves an address. DNS registration happens only
  after the lease is acknowledged.
- Active leases drive both forward A records and reverse PTR records. DNS TTLs
  are capped by the remaining lease lifetime. Client resolvers may retain a
  previously cached answer until its TTL expires after a release or rename.
- Renewals update the lease lifetime. Expired, released, or declined leases stop
  resolving. Declined addresses are temporarily quarantined from allocation.
- Hostnames are normalized to lowercase. Clients may supply a single label, such
  as `laptop`, or a fully qualified name under the configured local domain.
  Invalid or out-of-domain names, the reserved `ns` name, and duplicate names
  still receive a DHCP address but no DNS registration. A duplicate cannot
  replace another client's active record. A hostname supplied only during
  discovery is retained for the subsequent request; renewals that omit a name
  retain the previous registration.
- Lease state is saved on changes and restored at startup, including DNS names
  for leases that are still valid. Keep the lease file across restarts to avoid
  reallocating addresses that clients may still be using. In-memory operation
  intentionally loses lease state when the process exits. Persistence uses an
  atomic file replacement; a failed write prevents the corresponding lease
  change from being acknowledged. Only one process may own a lease file.
- Interrupt or terminate the process with SIGINT or SIGTERM to stop both servers.

This implementation serves one IPv4 subnet and one address pool. It does not
provide DHCPv6, static reservations, dynamic DNS UPDATE, DNSSEC validation, or
automatic ICMP/ARP probing for conflicting addresses. Client hostnames are
client-supplied labels, not authenticated identities. Configure the pool to
exclude all other equipment with static addresses.

## Development

```sh
go test -race ./...
go test -race -tags=integration ./...
go vet ./...
```

Unit tests exercise lease allocation, DHCP packet handling, DNS answers, and
configuration validation. Integration tests use local sockets on unprivileged
ports, so they can run without root or changing your network configuration.

The Makefile provides `make build`, `make test`, `make integration`, and
`make vet`; `make check` runs all checks. The binary is written to `bin/infra-box`.
