# Infrastructure-in-a-Box

A Go DHCPv4 server with built-in DNS, a private certificate authority, an
HTTPS gateway, and LDAP authentication. Clients receive an IPv4 lease and the
server's DNS address; their DHCP hostnames become local A and PTR records. `gateway.<domain>` serves
HTTPS using a certificate signed by the private CA and offers its public root
certificate for download.
An ACME v2 server issues certificates for active DHCP hostnames using HTTP-01.
DHCP packet handling uses `github.com/insomniacslk/dhcp/dhcpv4`, and DNS uses
`github.com/miekg/dns`.
Static DNS A records, including wildcard records, can also be configured for
services and devices or to override selected external DNS names.

## Build and run

Use the Go version declared in `go.mod` or newer:

```sh
go build -o bin/infra-box ./cmd/infra-box
```

Configure a static IPv4 address on the interface before starting the server. For
example, with `192.168.50.2/24` already assigned to `eth0`, an existing router at
`192.168.50.1`, and addresses `.100` through `.200` available for DHCP, copy the
example configuration:

```sh
cp config.example.json config.json
```

Edit `config.json` to match your interface, subnet, pool, router, and state
locations. The [example file](config.example.json) includes every supported
setting and stores persistent state under `/var/lib/infra-box`. Create that
directory, then start the server:

```sh
sudo install -d -m 0750 /var/lib/infra-box
sudo ./bin/infra-box -config config.json
```

The default configuration path is `config.json` in the current directory;
`-config /etc/infra-box/config.json` selects a different file. The file must
exist. Binding the default ports normally requires root or suitable
operating-system capabilities. Permit client traffic
to UDP port 67, UDP/TCP port 53, and TCP ports 389, 443, and 636. Only run one DHCP server for
this pool on the network, and keep statically assigned addresses outside the pool.

The `router` setting advertises an existing default gateway; the application does
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
startup. For `"domain": "home.arpa"`, visit `https://gateway.home.arpa/`. The built-in
DNS server always resolves `gateway.home.arpa` to `server_ip`, independently of
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
`<ca_dir>/root-ca.pem`. The gateway serves only this public certificate; it never
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
stores automatically. HTTPS always uses port 443.

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
configured domain and fixed HTTPS port 443. The API shares the gateway's
HTTPS listener and signs certificates under the existing private CA.

An ACME client generates and retains its own account and certificate private
keys. It requests a certificate for its fully qualified DHCP hostname, such as
`laptop.home.arpa`, and serves the challenge response at
`http://laptop.home.arpa/.well-known/acme-challenge/<token>`. The CA connects to
the client's current leased IPv4 address on **TCP port 80**. Permit that
connection from the infrastructure server and keep the challenge path available
for renewal. Port 80 belongs to the requesting client's HTTP listener; the ACME
API continues to use HTTPS on the gateway.

Only active, committed DHCP registrations beneath `domain` can obtain
certificates. The zone apex, reserved `gateway` and `ns` names, wildcard names,
IP identifiers, external names, and names known only through static or wildcard
DNS records or an upstream resolver are rejected. Validation connects directly
to the checked lease address within `subnet`; it does not use system DNS,
upstream DNS, or HTTP proxies. The
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
`<ca_dir>/acme.json` by default. Set `acme_state` to choose another persistent
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

## LDAP users and groups

The LDAPv3 server provides authentication and a read-only directory of users and
groups stored in the JSON configuration. It always starts both listeners,
including when the `ldap` object is omitted:

| Address | Protocol |
| --- | --- |
| `<server_ip>:389` | LDAP over plaintext TCP. |
| `<server_ip>:636` | LDAPS with TLS from connection establishment. |

Both listeners serve the same directory and authentication rules. Their address
comes from `server_ip`, and their ports are fixed. Remove `ldap.enabled`,
`ldap.listen`, and `ldap.tls` from older configuration files; those keys are no
longer accepted. Without configured users, no account can authenticate. Changes
take effect after a restart.

The [example configuration](config.example.json) includes two users, their
groups, and an application search account named `ldap-reader`. All example
accounts are disabled and contain no passwords. To use them:

1. Generate a different bcrypt password hash for each account you enable. For
   example, Apache's `htpasswd -nBC 12 johndoe` prompts for a password; copy the portion
   after `johndoe:` into that user's `pass_bcrypt` JSON string. Repeat for
   `ldap-reader` and any other accounts. Preserve the complete `$2...` hash.
2. Set those users' `disabled` fields to false.
3. Keep the configuration readable only by the service administrator, for
   example with `chmod 600 config.json`. Restart the server and allow TCP port
   389 for LDAP and port 636 for LDAPS from the clients that need access.
4. Give LDAPS clients the public root CA through the trusted channel described
   above, and configure them to verify the server certificate.

LDAPS uses a separate certificate for `ldap.<domain>` and `server_ip`, signed by
the existing private CA. Its private key and certificate are stored in
`<ca_dir>/ldap-bundle.pem` with mode `0600`, and renewed automatically on TLS
connections. Back it up with the rest of the CA directory. No ACME client is
needed for this built-in service. LDAP automatically adds the local
DNS A record `ldap.<domain>` pointing to `server_ip`, and reserves that name
against DHCP registrations. An explicit conflicting A record is rejected.
ACME cannot issue client certificates for that service name. Existing ACME state
remains readable after upgrading.

The nested settings are:

| LDAP key | Default | Meaning |
| --- | --- | --- |
| `base_dn` | Derived from `domain` | Directory suffix, such as `dc=home,dc=arpa`. |
| `users` | `[]` | User objects described below. |
| `groups` | `[]` | Objects with a unique `name` and positive numeric `gid`. |

Each user has a unique `name`, a `primary_group` referencing a configured group,
and exactly one password field when enabled. Optional fields are:

| User key | Meaning |
| --- | --- |
| `mail` | Email address exposed in directory searches. |
| `pass_bcrypt` | Standard bcrypt hash, including its salt and cost (4–14). Recommended; use cost 12. |
| `pass_sha256` | Legacy GLAuth-style hexadecimal SHA-256 password digest; supported for migration. Prefer bcrypt for new passwords. |
| `uid_number` | Optional positive, unique numeric Unix user ID. Omitting it creates an application account without the `posixAccount` object class. |
| `other_groups` | Additional group IDs. The primary group is included automatically; repeated memberships appear only once. |
| `disabled` | Defaults to false. Prevents authentication; the entry remains searchable. Disabled accounts may omit a password. |
| `can_search` | Defaults to false. Allows the account to search directory entries, including other users and groups. |

Names contain 1–64 ASCII characters: start with a letter or underscore, followed
by letters, digits, underscores, dots, or hyphens. User and group names are
unique without regard to case. Numeric IDs must fit a positive signed 32-bit
integer. Every primary and additional group must exist; for example, a user
referencing group `5511` requires a group with `"gid": 5511`. Do not specify both
password fields. Password hashes are never returned through LDAP.

User DNs have the stable form `uid=johndoe,ou=users,dc=home,dc=arpa`; group DNs
are `cn=team10_r,ou=groups,dc=home,dc=arpa`. Authenticate with the full user DN
and password. Bind names and DN attributes are matched without regard to case.
Application accounts with `can_search: true` can search for a user's DN and
groups, then the application can authenticate that user on a separate connection.
Ordinary users can bind but cannot search the directory. Anonymous clients can
read only the base-scope root DSE discovery entry.

After enabling `ldap-reader`, use OpenLDAP's client tools to test a verified TLS
connection. `-W` prompts for the account password:

```sh
LDAPTLS_CACERT=/path/to/root-ca.pem ldapsearch -LLL -x \
  -H ldaps://ldap.home.arpa:636 \
  -D 'uid=ldap-reader,ou=users,dc=home,dc=arpa' -W \
  -b 'dc=home,dc=arpa' '(uid=johndoe)' uid cn mail memberOf

LDAPTLS_CACERT=/path/to/root-ca.pem ldapsearch -LLL -x \
  -H ldaps://ldap.home.arpa:636 \
  -D 'uid=ldap-reader,ou=users,dc=home,dc=arpa' -W \
  -b 'ou=groups,dc=home,dc=arpa' \
  '(member=uid=johndoe,ou=users,dc=home,dc=arpa)' cn gidNumber memberUid
```

For plaintext LDAP, use `-H ldap://ldap.home.arpa:389` with the same bind DN,
password, and search base. The CA setting applies only to LDAPS. StartTLS is
not supported.

Users expose `inetOrgPerson` attributes and derived `memberOf` memberships.
Users with `uid_number` also expose `posixAccount`, `uidNumber`, `gidNumber`,
`homeDirectory` (`/home/<name>`), and `loginShell` (`/bin/sh`). Groups expose
`posixGroup` and `extensibleObject`, with `gidNumber`, `memberUid`, `member`, and
`uniqueMember`. Configure application group filters with `objectClass=posixGroup`
and `member=<user DN>`; group names alone do not assign application permissions.

Search supports base, one-level, and subtree scopes, attribute selection,
types-only responses, and equality, presence, substring, AND, OR, and NOT
filters. The service allows up to 1,000 results per search, 64 simultaneous
connections, four simultaneous password checks, and 20 bind attempts per
connection. Messages are limited to 64 KiB and idle connections to two minutes.
Searches, writes, and TLS handshakes have ten-second time limits; clients can
request smaller search limits.
Directory writes, password-change operations, StartTLS, SASL, and paged searches
are outside this version's scope. Unknown critical controls return an error;
noncritical controls may be ignored. Use `ldaps://` for TLS. All services stop
together on shutdown or a listener failure, so a restart also interrupts LDAP
authentication.

## Configuration

All service settings come from a single JSON file. Use `-config` to select the
file, or omit it to read `config.json` from the current directory. Run
`./bin/infra-box -h` for command-line help. Service flags and environment-variable
overrides are not supported. The file is read and validated at startup; restart
the server after editing it.

The file must contain one JSON object using the exact, lowercase keys below.
Values are strings, including durations and listener addresses, except for
`a_records`, which maps DNS names to IPv4 strings, and the nested `ldap` object
described above. Omitted
optional settings use their defaults. Unknown or duplicate keys, `null`, invalid
value types, comments, trailing commas, and additional JSON values are rejected.
The maximum file size is 1 MiB.

| JSON key | Default when omitted | Meaning |
| --- | --- | --- |
| `interface` | required | Interface serving DHCP. |
| `server_ip` | required | Static IPv4 address of this server, also advertised as the DNS server. |
| `subnet` | required | Canonical IPv4 CIDR subnet, such as `192.168.50.0/24`. |
| `pool_start` | required | First address in the DHCP pool. |
| `pool_end` | required | Last address in the DHCP pool, inclusive. |
| `router` | `""` | Existing default gateway to advertise; empty disables advertising a router. |
| `domain` | `home.arpa` | Domain for DHCP hostnames. |
| `lease_duration` | `12h` | Lease lifetime, in whole seconds, at least `1m`. |
| `lease_file` | `leases.json` | Persisted lease state; set to `""` for memory only. |
| `dhcp_listen` | `:67` | DHCP UDP listener. |
| `upstream` | `""` | Optional numeric IPv4 address and port for external DNS, such as `1.1.1.1:53`; empty disables forwarding. |
| `dns_ttl` | `1m` | Maximum TTL for DNS records, in whole seconds, at least `1s`. |
| `a_records` | `{}` | Exact or wildcard DNS names mapped to IPv4 address strings, including external-name overrides. |
| `ca_dir` | `pki` | Persistent directory for the private CA and service certificates. |
| `acme_state` | `<ca_dir>/acme.json` | Persistent ACME accounts, orders, certificates, and revocations; empty also selects this default. Must differ from the lease and CA certificate/key files. |
| `ldap` | LDAP on `<server_ip>:389`; LDAPS on `<server_ip>:636` | Directory suffix, users, groups, and search permissions for both always-running listeners. See above. |

Durations use Go duration strings such as `"12h"`, `"30m"`, or `"60s"` and must
represent a whole number of seconds. File and directory paths are resolved
relative to the configuration file's directory, including default paths.
Absolute paths remain unchanged. For example, a file at
`/etc/infra-box/config.json` with `"ca_dir": "pki"` stores the CA in
`/etc/infra-box/pki`; an omitted `acme_state` then becomes
`/etc/infra-box/pki/acme.json`. An explicit relative `acme_state` is relative to
the configuration file, not to `ca_dir`. Paths do not expand `~` or environment
variables.

To migrate an existing launch command, move each service flag into the JSON
object, remove its leading hyphen, and replace hyphens in its name with
underscores. For example, `-server-ip 192.168.50.2` becomes
`"server_ip": "192.168.50.2"`. Replace the service flags in the launch command
with `-config /path/to/config.json`. Keep existing state paths absolute, or
adjust relative paths for the configuration file's location, so the server
continues using the same leases, CA, and ACME state.

DNS always listens on `<server_ip>:53` for UDP and TCP, and HTTPS always listens
on `<server_ip>:443`. Remove `dns_listen` and `https_listen` from older
configuration files; those keys are no longer accepted. The DHCP listener
accepts `:port`, `0.0.0.0:port`, or `<server_ip>:port`. Alternate DHCP ports
support development, but normal DHCP clients expect port 67. Hostname-based upstream
addresses are rejected to avoid depending on DNS during startup. An upstream
must not point back to the DNS listener.

Without an upstream, DNS answers the local zone and configured A record
overrides. To resolve other public names, add `"upstream": "1.1.1.1:53"` or the
address of your existing resolver. Local names and matching overrides are
answered locally. Unmatched external names are forwarded to the upstream, or
receive `REFUSED` when no upstream is configured. Restrict access to the DNS
ports to the network you intend to serve, particularly when forwarding is enabled.

## Static DNS A records

Add an `a_records` object to the JSON configuration, then restart the server:

```json
"a_records": {
  "printer": "192.168.50.10",
  "nas.home.arpa": "192.168.50.20",
  "*.apps.home.arpa": "192.168.50.20",
  "@": "192.168.50.2"
}
```

With `"domain": "home.arpa"`, the exact records resolve `printer.home.arpa`,
`nas.home.arpa`, and `home.arpa`. Single hostnames are relative to the configured
domain; `@` means the domain itself. Names with multiple labels, such as
`nas.home.arpa` or `google.com`, are used as written and may be outside the local
domain. Names are case insensitive, and fully qualified names may end in a dot.
Duplicate names after normalization and the reserved exact local names
`ns.home.arpa` and `gateway.home.arpa` are rejected. Each entry maps to one
unicast IPv4 address.

Static records are served over both UDP and TCP with the configured `dns_ttl`.
They remain available independently of DHCP lease expiry. Exact static records
within the local domain take precedence over DHCP registrations. DHCP clients
attempting to register an exact local static name still receive an address, but
no DNS name; an existing lease that conflicts with a new exact local static name
keeps its address and loses that hostname. External entries do not reserve DHCP
names.

For wildcard records, use `*` or `*.home.arpa` for the zone, or
`*.apps.home.arpa` for a subdomain. The relative form `*.apps` also becomes
`*.apps.home.arpa`; `*.google.com` applies to the external name as written.
Only a complete leftmost `*` label is allowed; partial or
multiple wildcards such as `app*` or `*.*.home.arpa` are rejected. Wildcards are
used after infrastructure names, exact static records, and active DHCP names.
They do not reserve matching DHCP names, so a client can register a name covered
by a wildcard and receive its own DNS record.

Wildcard matching follows the closest-encloser rules in
[RFC 4592](https://www.rfc-editor.org/rfc/rfc4592.html#section-3.3.1): missing
names can match at any depth, but an existing name or intervening parent blocks
a broader wildcard. Parents implied by child records count as existing names.
For example, `*.apps.home.arpa` can answer both `shop.apps.home.arpa` and
`api.dev.apps.home.arpa` while `dev.apps.home.arpa` has no records or children.
Adding `status.dev.apps.home.arpa` creates that parent and prevents
`api.dev.apps.home.arpa` from using `*.apps.home.arpa`; add `*.dev.apps.home.arpa`
to provide a wildcard there. A wildcard never matches its own parent, so
`*.apps.home.arpa` does not supply an A record for `apps.home.arpa` itself.

To override an external domain and its otherwise unmatched descendants, add
both exact and wildcard entries:

```json
"a_records": {
  "google.com": "192.168.50.20",
  "*.google.com": "192.168.50.20"
}
```

The exact entry answers for `google.com`; the wildcard can answer for
`www.google.com`. An exact entry alone does not override `www.google.com`, and
the wildcard alone does not override `google.com`. Other external names continue
to use the upstream, or receive `REFUSED` when it is unset. Wildcard matching
uses configured names and their implied parents; it does not query the upstream
to discover which external names exist. A closer configured ancestor can
therefore block a broader wildcard, just as in the local example above.

Matching external overrides are handled before forwarding for every query
type. `A` and `ANY` queries receive the configured A record; `AAAA`, `TXT`, and
other query types receive a local `NODATA` response (success with no answers),
rather than data from the upstream.

These entries create A records only. They do not create PTR records or DHCP IP
reservations. For devices configured with fixed IPs, use addresses outside the
DHCP pool. Targets may also be reachable IPv4 addresses outside the local subnet.
ACME authorization still requires an exact, active DHCP registration. A name
resolved only through a static or wildcard record is not eligible, and wildcard
certificates are not supported. External overrides do not enable certificate
issuance outside the configured local domain. Restart after editing `a_records`;
cached DNS answers may remain until their TTL expires.

Check the local and external examples over both DNS transports:

```sh
dig @192.168.50.2 printer.home.arpa A
dig +tcp @192.168.50.2 nas.home.arpa A
dig @192.168.50.2 shop.apps.home.arpa A
dig @192.168.50.2 google.com A
dig +tcp @192.168.50.2 www.google.com A
```

## Lease and DNS behavior

- A DHCP offer temporarily reserves an address. DNS registration happens only
  after the lease is acknowledged.
- Active leases drive both forward A records and reverse PTR records. DNS TTLs
  are capped by the remaining lease lifetime. Client resolvers may retain a
  previously cached answer until its TTL expires after a release or rename.
- Renewals update the lease lifetime. Expired, released, or declined leases lose
  their DHCP DNS records; a configured wildcard may then answer for the name.
  Declined addresses are temporarily quarantined from allocation.
- Hostnames are normalized to lowercase. Clients may supply a single label, such
  as `laptop`, or a fully qualified name under the configured local domain.
  Invalid or out-of-domain names, names reserved by exact static A records, the
  reserved `ns` and `gateway` names, and duplicate names still receive a DHCP
  address but no DNS registration. A
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
  HTTPS, and LDAP together. A listener failure also stops the other services.

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
validation, LDAP authentication and directory access, plus ACME signed requests
and HTTP-01 validation policy.
Integration tests use local sockets on unprivileged
ports, so they can run without root or changing your network configuration.
HTTPS tests trust only their generated private root and verify the real TLS
handshake and certificate downloads.
LDAP integration tests use loopback sockets and an independent LDAP client to
exercise binds, searches, group membership, and access restrictions.

The Makefile provides `make build`, `make test`, `make integration`, `make vet`,
and `make lint`; `make check` runs all of them except the build. The binary is
written to `bin/infra-box`. `make lint` runs the pinned golangci-lint version and
checks formatting; its first run downloads the lint tool. If that version is
already installed, use `make lint GOLANGCI_LINT=golangci-lint`.

[GitHub Actions](.github/workflows/ci.yml) runs on pushes, pull requests, and
manual dispatch. It builds the application and runs both test suites with race
detection, shuffled order, and test caching disabled. A separate lint job checks
module consistency, `go vet`, golangci-lint (including integration tests), Go
formatting, and known vulnerabilities with `govulncheck`. The workflow uses the
latest Go 1.26 patch release and read-only repository permissions.
