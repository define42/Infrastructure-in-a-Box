# Infrastructure-in-a-Box

A Go DHCPv4 server with built-in DNS, a private certificate authority, and an
HTTPS gateway. Clients receive an IPv4 lease and the server's DNS address;
their DHCP hostnames become local A and PTR records. `gateway.<domain>` serves
HTTPS using a certificate signed by the private CA and offers its public root
certificate for download.
An ACME v2 server issues certificates for active DHCP hostnames using HTTP-01.
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
  -lease-file /var/lib/infra-box/leases.json \
  -ca-dir /var/lib/infra-box/pki
```

Create the lease file's parent directory before running that example:
`sudo install -d -m 0750 /var/lib/infra-box`. Binding the default ports normally
requires root or suitable operating-system capabilities. Permit client traffic
to UDP port 67, UDP/TCP port 53, and TCP port 443. Only run one DHCP server for
this pool on the network, and keep statically assigned addresses outside the pool.

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

## HTTPS gateway and private CA

The server creates its private CA and a signed gateway certificate at first
startup. For `-domain home.arpa`, visit `https://gateway.home.arpa/`. The built-in
DNS server always resolves `gateway.home.arpa` to `-server-ip`, independently of
DHCP leases. The certificate covers both `gateway.home.arpa` and the server IP,
so `https://192.168.50.2/` also works after the root has been trusted.

The gateway page displays the root certificate's SHA-256 fingerprint and offers:

| URL | Download |
| --- | --- |
| `https://gateway.home.arpa/ca.pem` | Public CA root certificate in PEM format. |
| `https://gateway.home.arpa/ca.crt` | The same public certificate in DER format. |

The private CA is initially unknown to clients, so a browser will report an
untrusted issuer until its root certificate has been installed in the client's
trusted root store. For the first connection, obtain the public `root-ca.pem`
file from the server through a trusted administrator channel. Its location is
`<ca-dir>/root-ca.pem`. The gateway serves only this public certificate; it never
serves private keys or exposes the CA directory as a file server.

On the server, check the fingerprint against the HTTPS startup log:

```sh
sudo openssl x509 -in /var/lib/infra-box/pki/root-ca.pem \
  -noout -fingerprint -sha256
```

After copying that public PEM certificate to a client as `root-ca.pem`, download
the DER certificate over verified HTTPS, even before configuring client DNS:

```sh
curl --cacert root-ca.pem \
  --resolve gateway.home.arpa:443:192.168.50.2 \
  https://gateway.home.arpa/ca.crt --output root-ca.crt
openssl x509 -inform DER -in root-ca.crt -noout -fingerprint -sha256
```

Install the public root in the operating system or browser's trusted root store
to enable normal HTTPS access. The application does not change client trust
stores automatically. If `-https-listen` uses another port, include that port in
the gateway URL and in `curl --resolve`.

The CA uses ECDSA P-256 and is valid for ten years. Gateway certificates last up
to 90 days and renew automatically at startup or a TLS handshake when 30 days
or less remain. Changing the configured domain or server IP issues a new
gateway certificate under the existing CA. The root is never silently rotated;
an expired or invalid root requires an administrator to repair or replace the CA
and distribute the appropriate public root.

Keep the CA directory across restarts and back it up privately. It contains
`root-ca-bundle.pem` and `gateway-bundle.pem`, each holding a certificate and its
private key with mode `0600`, inside a `0700` directory. The separate
`root-ca.pem` export contains only the public root. Distribute that public export,
not the private bundles. Certificates and keys are replaced as atomic bundles;
invalid or incomplete private state causes startup to fail rather than creating
an unrelated CA. Only one server process may own a CA directory.

## ACME certificates with HTTP-01

The ACME directory is `https://gateway.home.arpa/acme/directory`, using the
configured domain and HTTPS port. With `-https-listen :8443`, use
`https://gateway.home.arpa:8443/acme/directory`. The API shares the gateway's
HTTPS listener and signs certificates under the existing private CA.

An ACME client generates and retains its own account and certificate private
keys. It requests a certificate for its fully qualified DHCP hostname, such as
`laptop.home.arpa`, and serves the challenge response at
`http://laptop.home.arpa/.well-known/acme-challenge/<token>`. The CA connects to
the client's current leased IPv4 address on **TCP port 80**. Permit that
connection from the infrastructure server and keep the challenge path available
for renewal. Port 80 belongs to the requesting client's HTTP listener; the ACME
API continues to use HTTPS on the gateway.

Only active, committed DHCP registrations beneath `-domain` can obtain
certificates. The zone apex, reserved `gateway` and `ns` names, wildcard names,
IP identifiers, external names, and names known only to an upstream resolver
are rejected. Validation connects directly to the checked lease address within
`-subnet`; it does not use system DNS, upstream DNS, or HTTP proxies. The
challenge must return HTTP 200 directly: redirects are rejected. Validation
has a five-second timeout and rechecks the lease owner and address before
accepting the result. Every new order requires fresh authorization.

After securely obtaining the public root as described above, a
[Certbot standalone client](https://eff-certbot.readthedocs.io/en/stable/using.html#standalone)
can request a certificate on the DHCP client. Replace the hostname, contact
email, and local public root path in this example:

```sh
sudo env REQUESTS_CA_BUNDLE=/etc/infra-box/root-ca.pem \
  certbot certonly \
  --server https://gateway.home.arpa/acme/directory \
  --standalone --preferred-challenges http \
  --domain laptop.home.arpa \
  --email you@example.net --agree-tos
```

Certbot must be able to bind the client's port 80. For an existing HTTP server,
use its webroot integration and serve the challenge path without redirecting
it. `REQUESTS_CA_BUNDLE` tells Certbot to verify the gateway against this private
root; keep it available for renewals as well. These options are documented in
the [Certbot command reference](https://eff-certbot.readthedocs.io/en/stable/man/certbot.html).

Configure the client's HTTPS service to use the certificate and key saved by
Certbot, and arrange renewal and service reloads with that client's normal
renewal mechanism. A manual renewal check uses:

```sh
sudo env REQUESTS_CA_BUNDLE=/etc/infra-box/root-ca.pem certbot renew
```

Issued certificates are valid for up to 90 days, capped by root expiry. Client
devices connecting to those services must also trust the private root. Losing a
DHCP lease does not revoke an already issued certificate; retain control of
the hostname or revoke the certificate when retiring a service. DHCP hostnames
remain client-supplied names, so this CA is intended for a trusted private
network.

ACME accounts, orders, issued certificates, and revocations are persisted in
`<ca-dir>/acme.json` by default. Use `-acme-state` to choose another persistent
file, and back it up together with the CA and lease state. Its permissions are
`0600`; it contains account public keys, not client private keys. Only one
server process may own these files. Keep the configured domain and HTTPS origin
stable so existing clients' account and order URLs continue to work.

Certificates can be revoked using the issuing account, the certificate's private
key, or an active account with valid HTTP-01 authorizations for every certificate
hostname that still match the current DHCP leases. Signed revocation lists are available
at `https://gateway.home.arpa/acme/crl`, also recorded in issued certificates'
CRL distribution points. Applications must explicitly check the CRL for
revocation to take effect; there is no OCSP responder. This version supports
HTTP-01 only, with no DNS-01 or TLS-ALPN-01 challenge support.

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
| `-https-listen` | `<server-ip>:443` | Gateway HTTPS TCP listener. |
| `-ca-dir` | `pki` | Persistent directory for the private CA and gateway certificates. |
| `-acme-state` | `<ca-dir>/acme.json` | Persistent ACME accounts, orders, certificates, and revocations. Must differ from the lease and CA certificate/key files. |

All listeners accept `:port`, `0.0.0.0:port`, or `<server-ip>:port`. Alternate
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
  Invalid or out-of-domain names, the reserved `ns` and `gateway` names, and
  duplicate names still receive a DHCP address but no DNS registration. A
  duplicate cannot replace another client's active record. A hostname supplied only during
  discovery is retained for the subsequent request; renewals that omit a name
  retain the previous registration.
  A persisted lease named `gateway.<domain>` from an older version retains its
  address and expiry on upgrade, but loses that hostname so it cannot replace
  the HTTPS gateway's DNS record.
- Lease state is saved on changes and restored at startup, including DNS names
  for leases that are still valid. Keep the lease file across restarts to avoid
  reallocating addresses that clients may still be using. In-memory operation
  intentionally loses lease state when the process exits. Persistence uses an
  atomic file replacement; a failed write prevents the corresponding lease
  change from being acknowledged. Only one process may own a lease file.
- Interrupt or terminate the process with SIGINT or SIGTERM to stop DHCP, DNS,
  and HTTPS together. A listener failure also stops the other services.

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

Unit tests exercise lease allocation, DHCP packet handling, DNS answers,
certificate generation and renewal, public CA downloads, and configuration
validation, plus ACME signed requests and HTTP-01 validation policy.
Integration tests use local sockets on unprivileged
ports, so they can run without root or changing your network configuration.
HTTPS tests trust only their generated private root and verify the real TLS
handshake and certificate downloads.

The Makefile provides `make build`, `make test`, `make integration`, and
`make vet`; `make check` runs all checks. The binary is written to `bin/infra-box`.
