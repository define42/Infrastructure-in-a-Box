# Infrastructure-in-a-Box

Infrastructure-in-a-Box is a single Go application that provides the core
services for a private IPv4 network: automatic IP addresses, local DNS names,
PXE boot files, HTTPS certificates, and a directory of users and groups. It
brings DHCP, DNS, TFTP, a private certificate authority, ACME, LDAP, and optional NFSv4 shares together in one process,
configured through one JSON file.

[![Go version](https://img.shields.io/badge/Go-1.26%2B-00ADD8)](go.mod)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

Use it for a home network or lab where devices and applications need to find
one another by name, use certificates from a shared private CA, and authenticate
users through LDAP.

| Service | What it provides |
| --- | --- |
| DHCPv4 | IPv4 leases from one address pool, with DNS and optional router settings sent to clients. |
| TFTP and PXE | Built-in iPXE loaders with DHCP selecting the BIOS or x64 EFI loader from client architecture option 93. |
| DNS | Local names and reverse lookups for active DHCP leases, static and wildcard A records, and optional forwarding to an upstream resolver. |
| Private CA and ACME | Certificates for active DHCP hostnames through ACME HTTP-01, plus certificates for the built-in HTTPS and LDAPS services. |
| HTTP and HTTPS gateway | A page for downloading the public root CA and checking its fingerprint, plus read-only boot files. The ACME API uses HTTPS. |
| LDAP and LDAPS | Password authentication and a read-only directory of configured users and groups. |
| NFSv4.0 | Optional directory shares with per-share read-only access. |

For example, a laptop joining the network can receive `192.168.50.100` and
register `laptop.home.arpa`. Other devices can resolve that name immediately.
An ACME client on the laptop can then request a certificate for
`laptop.home.arpa` by answering an HTTP-01 challenge. Applications can separately
use `ldap.home.arpa` to authenticate users from the configured directory.

```text
DHCP lease:       laptop → 192.168.50.100
Forward DNS:      laptop.home.arpa → 192.168.50.100
Reverse DNS:      192.168.50.100 → laptop.home.arpa
ACME directory:   https://gateway.home.arpa/acme/directory
User directory:   ldaps://ldap.home.arpa:636
```

This example uses the default `home.arpa` domain; the actual client address
comes from the configured pool. Certificates become trusted after clients
install the private root CA. DHCP hostnames are supplied by clients, so
certificate issuance assumes a trusted private network.

Read on for [getting started](#getting-started), [configuration](#configuration),
[DHCP and DNS behavior](#lease-and-dns-behavior),
[PXE network boot](#pxe-network-boot),
[static DNS records](#static-dns-a-records),
[the private CA](#http-and-https-gateway-and-private-ca),
[ACME certificates](#acme-certificates-with-http-01),
[LDAP users and groups](#ldap-users-and-groups), and
[contributing](#contributing).

## Getting started

### Prepare the network

Choose an interface with a static IPv4 address and a DHCP pool that excludes
all statically assigned devices. The server address and optional router must
be usable addresses in the subnet, outside the pool. Run only one DHCP server
for this pool on the network.

The examples below assume:

| Setting | Example |
| --- | --- |
| Server interface | `eth0`, already configured with `192.168.50.2/24` |
| Subnet | `192.168.50.0/24` |
| Available DHCP pool | `192.168.50.100` through `192.168.50.200` |
| Existing router | `192.168.50.1` |
| Local domain | `home.arpa` |
| Persistent state directory | `/var/lib/infra-box` |

The `router` setting advertises your existing default gateway. Configure the
host's interfaces and routing separately; Infrastructure-in-a-Box does not
provide routing or NAT. Omit `router` if clients should not receive a default
gateway.

### Build from source

Use the Go version declared in [go.mod](go.mod) or newer. From a checkout of
this repository:

```sh
go build -o bin/infra-box ./cmd/infra-box
```

The build embeds the iPXE loaders in `ipxe/`. Run `./build-ipxe.sh` before
building Go to regenerate them; see [PXE network boot](#pxe-network-boot).

### Configure and start

Copy the [example configuration](config.example.json):

```sh
cp config.example.json config.json
chmod 600 config.json
```

Edit `config.json` to match your interface, subnet, pool, router, and state
locations. The example includes every supported top-level setting and stores
persistent state under `/var/lib/infra-box`. Its LDAP accounts are disabled
until you set their password hashes and enable them. Create the example NFS
directories `/var/data` and `/srv/software` before starting, or set `"nfs": []`
to leave file sharing disabled.

External DNS forwarding is disabled in the example. To resolve public names,
set `upstream` to your existing resolver's numeric IPv4 address and port, such
as `"1.1.1.1:53"`. See [configuration](#configuration) for all settings.

Create the state directory, then start the server:

```sh
sudo install -d -m 0750 /var/lib/infra-box
sudo ./bin/infra-box -config config.json
```

The configuration file must exist. Omitting `-config` reads `config.json` from
the current directory. Binding the default ports normally requires root or
suitable operating-system capabilities. Permit client traffic to these ports:

| Service | Default listener | Transport |
| --- | --- | --- |
| DHCP | `:67` on the configured interface | UDP |
| DNS | `<server_ip>:53` | UDP and TCP |
| TFTP | `<server_ip>:69` | UDP; each transfer uses an additional ephemeral UDP port |
| HTTP gateway | `<server_ip>:80` | TCP |
| HTTPS gateway and ACME | `<server_ip>:443` | TCP |
| LDAP | `<server_ip>:389` | Plaintext TCP |
| LDAPS | `<server_ip>:636` | TLS over TCP |
| NFSv4.0 | `<server_ip>:2049` | TCP; enabled when `nfs` contains shares |

All services start together, including both LDAP listeners even when no users
are configured. TFTP always serves the built-in iPXE loaders. Both HTTP and
HTTPS are always enabled. DNS, TFTP, HTTP, HTTPS, LDAP,
LDAPS, and NFS ports are fixed. Configuration changes take effect after a restart.

### Check a client lease

Connect a DHCP client that announces the hostname `laptop`. After it acquires a
lease, use its actual assigned address to check forward and reverse DNS:

```sh
dig @192.168.50.2 laptop.home.arpa A
dig @192.168.50.2 -x 192.168.50.100
dig +tcp @192.168.50.2 laptop.home.arpa A
```

For HTTPS and LDAPS, first [obtain and trust the public root
CA](#http-and-https-gateway-and-private-ca). You can then visit
`https://gateway.home.arpa/`, configure an
[ACME client](#acme-certificates-with-http-01), or enable
[LDAP accounts](#ldap-users-and-groups).

## Features and configuration

### Configuration

All service settings come from a single JSON file. Use `-config` to select the
file, or omit it to read `config.json` from the current directory. Run
`./bin/infra-box -h` for command-line help. Service flags and environment-variable
overrides are not supported. The file is read and validated at startup; restart
the server after editing it.

The file must contain one JSON object using the exact, lowercase keys below.
Values are strings, including durations and listener addresses, except for
`a_records`, which maps DNS names to IPv4 strings, the nested `ldap` object
described in [LDAP users and groups](#ldap-users-and-groups), and the `nfs` array
described in [NFS shares](#nfs-shares). Omitted
optional settings use their defaults. Unknown or duplicate keys, `null`, invalid
value types, comments, trailing commas, and additional JSON values are rejected.
The maximum file size is 1 MiB.

| JSON key | Default when omitted | Meaning |
| --- | --- | --- |
| `interface` | required | Interface serving DHCP. |
| `server_ip` | required | Static IPv4 address of this server, also advertised as the DNS and PXE boot server. |
| `subnet` | required | Canonical IPv4 CIDR subnet, such as `192.168.50.0/24`. |
| `pool_start` | required | First address in the DHCP pool. |
| `pool_end` | required | Last address in the DHCP pool, inclusive. |
| `router` | `""` | Existing default gateway to advertise; empty disables advertising a router. |
| `domain` | `home.arpa` | Domain for DHCP hostnames. |
| `lease_duration` | `12h` | Lease lifetime, in whole seconds, at least `1m`. |
| `lease_file` | `leases.json` | Persisted lease state; set to `""` for memory only. |
| `dhcp_listen` | `:67` | DHCP UDP listener; must not conflict with DNS or TFTP. |
| `boot_root` | `tftp` | Directory of public HTTP/HTTPS `/boot/` files, created if absent; TFTP serves only built-in loaders. Cannot be empty, contain the configuration or private state, or reside inside `ca_dir`. |
| `upstream` | `""` | Optional numeric IPv4 address and port for external DNS, such as `1.1.1.1:53`; empty disables forwarding. |
| `dns_ttl` | `1m` | Maximum TTL for DNS records, in whole seconds, at least `1s`. |
| `a_records` | `{}` | Exact or wildcard DNS names mapped to IPv4 address strings, including external-name overrides. |
| `ca_dir` | `pki` | Persistent directory for the private CA and service certificates. |
| `acme_state` | `<ca_dir>/acme.json` | Persistent ACME accounts, orders, certificates, and revocations; empty also selects this default. Must differ from the lease and CA certificate/key files. |
| `nfs` | `[]` (disabled) | Directory shares served on `<server_ip>:2049`; see [NFS shares](#nfs-shares). |
| `ldap` | LDAP on `<server_ip>:389`; LDAPS on `<server_ip>:636` | Directory suffix, users, groups, and search permissions for both always-running listeners. See [LDAP users and groups](#ldap-users-and-groups). |

Durations use Go duration strings such as `"12h"`, `"30m"`, or `"60s"` and must
represent a whole number of seconds. NFS share paths must be absolute. Other file and directory paths are resolved
relative to the configuration file's directory, including default paths.
Absolute paths remain unchanged. For example, a file at
`/etc/infra-box/config.json` with `"ca_dir": "pki"` stores the CA in
`/etc/infra-box/pki`; an omitted `acme_state` then becomes
`/etc/infra-box/pki/acme.json`. An explicit relative `acme_state` is relative to
the configuration file, not to `ca_dir`. Paths do not expand `~` or environment
variables.

For existing configurations, rename `tftp_root` to `boot_root` and keep its
directory value unchanged. The old key is no longer accepted; boot files do not
need to move.

To migrate an existing launch command, move each service flag into the JSON
object, remove its leading hyphen, and replace hyphens in its name with
underscores. For example, `-server-ip 192.168.50.2` becomes
`"server_ip": "192.168.50.2"`. Replace the service flags in the launch command
with `-config /path/to/config.json`. Keep existing state paths absolute, or
adjust relative paths for the configuration file's location, so the server
continues using the same leases, CA, and ACME state.

DNS always listens on `<server_ip>:53` for UDP and TCP. The gateway always listens
on `<server_ip>:80` for HTTP and `<server_ip>:443` for HTTPS. Ensure both TCP ports
are available when upgrading. Remove `dns_listen` and `https_listen` from older
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

### Lease and DNS behavior

Clients must supply a hostname through DHCP to receive a DNS name. The server
uses Client FQDN option 81 when present, otherwise Host Name option 12, and honors
option 81's request to skip DNS registration. The local domain is advertised in
domain option 15 and search-list option 119 so clients can resolve short names.
`ns.home.arpa` identifies the built-in DNS server. The default domain,
[`home.arpa`](https://www.rfc-editor.org/rfc/rfc8375.html), is reserved for home
networks; avoid `.local`, which is reserved for
[multicast DNS](https://www.rfc-editor.org/rfc/rfc6762.html).

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
  reserved `ns`, `gateway`, and `ldap` names, and duplicate names still receive a DHCP
  address but no DNS registration. A duplicate cannot replace another client's
  active record. A hostname supplied only during discovery is retained for the subsequent request; renewals that omit a name
  retain the previous registration.
  A persisted lease named `gateway.<domain>` from an older version retains its
  address and expiry on upgrade, but loses that hostname so it cannot replace
  the gateway's DNS record.
- Lease state is saved on changes and restored at startup, including DNS names
  for leases that are still valid. Keep the lease file across restarts to avoid
  reallocating addresses that clients may still be using. In-memory operation
  intentionally loses lease state when the process exits. Persistence uses an
  atomic file replacement; a failed write prevents the corresponding lease
  change from being acknowledged. Only one process may own a lease file.
- Interrupt or terminate the process with SIGINT or SIGTERM to stop DHCP, DNS,
  TFTP, HTTP, HTTPS, LDAP, LDAPS, and configured NFS shares together. A listener failure also stops the
  other services.

This implementation serves one IPv4 subnet and one address pool. It does not
provide DHCPv6, static reservations, dynamic DNS UPDATE, DNSSEC validation, or
automatic ICMP/ARP probing for conflicting addresses. Client hostnames are
client-supplied labels, not authenticated identities. Configure the pool to
exclude all other equipment with static addresses.

### Static DNS A records

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

### PXE network boot

The always-enabled TFTP server listens on `<server_ip>:69` and serves exactly
two files embedded in the application: `pxelinux.0` (BIOS iPXE) and `bootx64.efi`
(x64 UEFI iPXE). It never reads runtime files from disk. Both loaders obtain DHCP
settings and load the main boot script over HTTP using this embedded bootstrap:

```ipxe
#!ipxe
dhcp
chain http://${next-server}/boot/boot.ipxe
```

DHCP supplies `${next-server}`, so the loaders work across installations without
a hardcoded IP address. The `pxelinux.0` filename contains iPXE; no PXELINUX
modules or configuration are needed. The EFI loader is unsigned.

DHCP OFFER and ACK replies select a boot filename from option **93 — Client
System Architecture**:

| Architecture | Boot filename |
| --- | --- |
| 0 — BIOS / x86 | `pxelinux.0` |
| 7 — EFI BC | `bootx64.efi` |
| 9 — EFI x86-64 | `bootx64.efi` |
| Other values, including 6 and 11, or missing/malformed option 93 | No boot filename |

For a client listing multiple architectures, the first supported value wins.
Replies include the boot-server IPv4 address in `siaddr`, the filename in the
BOOTP file field, and DHCP options 66 and 67. Ordinary DHCP clients continue to
receive leases without boot instructions.

Place `boot.ipxe`, kernels, initramfs files, and operating-system images in
`boot_root`, the public HTTP and HTTPS `/boot/` directory. For example:

```text
/var/lib/infra-box/tftp/
├── boot.ipxe
└── slax/
    ├── vmlinuz
    ├── initrfs.img
    └── slax.iso
```

For [Slax](https://www.slax.org/en/starting.php), use a matching kernel,
network-enabled initramfs, and ISO, with this `boot.ipxe`:

```ipxe
#!ipxe
set base http://${next-server}/boot/slax
kernel ${base}/vmlinuz rw load_ramdisk=1 prompt_ramdisk=0 from=${base}/slax.iso
initrd ${base}/initrfs.img
boot
```

The gateway serves these files at `http://gateway.<domain>/boot/` and
`https://gateway.<domain>/boot/`, with directory browsing, HEAD, and byte-range
downloads. HTTP serves files directly without redirecting to HTTPS, allowing
the Slax initramfs to access its ISO without HTTPS or private CA support.
HTTPS clients must trust the private root CA. Web file updates take effect
without a restart.

Relative `boot_root` paths resolve beside the JSON configuration file; the
default is a sibling directory named `tftp`. The example configuration uses
`/var/lib/infra-box/tftp`. The gateway creates an absent directory at startup.
An unusable directory or occupied listener stops the application along with
its other services.

To update the built-in loaders, run `./build-ipxe.sh`. It downloads the
[upstream source](https://ipxe.org/download) and writes both binaries, the
embedded bootstrap, and the source commit to the repository's `ipxe/` directory.
Then run `make build` or `go build -o bin/infra-box ./cmd/infra-box` and restart
the application. The running server needs no loader directory. Use
`./build-ipxe.sh --help` for dependencies and the `IPXE_REF` and `IPXE_JOBS`
settings.

Select network boot in the client firmware.
To check a file transfer independently of firmware, run from a client:

```sh
curl --noproxy '*' tftp://192.168.50.2/pxelinux.0 -o /tmp/pxelinux.0
```

Transfers use binary (`octet`) mode. The server supports `blksize` (up to 1468
bytes), `tsize`, and `timeout` negotiation, with standard 512-byte blocks when
options are absent. Unknown options are omitted. Only the two built-in loader
filenames can be downloaded; other filenames, paths, and uploads are rejected.
TFTP has no directory listing or client authentication. The HTTP and HTTPS
`/boot/` directory is also public; keep only public boot assets there. Web
downloads reject traversal and symlink escapes outside `boot_root`.

Permit UDP port 69 and replies from the server's ephemeral transfer ports, plus
TCP ports 80 and 443 for web downloads, in any firewall between the client and
server. The TFTP server allows 64 simultaneous transfers, at most four per
client IP, retries unacknowledged packets up to five
attempts, and limits each transfer to ten minutes. Cancellation closes the
listener and active transfers together.

### HTTP and HTTPS gateway and private CA

The server creates its private CA and a signed gateway certificate at first
startup. For `"domain": "home.arpa"`, visit `https://gateway.home.arpa/`. The built-in
DNS server always resolves `gateway.home.arpa` to `server_ip`, independently of
DHCP leases. The certificate covers both `gateway.home.arpa` and the server IP,
so `https://192.168.50.2/` also works after the root has been trusted.

The same gateway page, public CA downloads, and `/boot/` files are available over
HTTP at `http://gateway.home.arpa/` or `http://192.168.50.2/`. HTTP and HTTPS run
simultaneously on ports 80 and 443, respectively; HTTP requests are served
directly without redirecting to HTTPS. The ACME API requires HTTPS.

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

### ACME certificates with HTTP-01

The ACME directory is `https://gateway.home.arpa/acme/directory`, using the
configured domain and fixed HTTPS port 443. The API shares the gateway's
HTTPS listener and signs certificates under the existing private CA.

An ACME client generates and retains its own account and certificate private
keys. It requests a certificate for its fully qualified DHCP hostname, such as
`laptop.home.arpa`, and serves the challenge response at
`http://laptop.home.arpa/.well-known/acme-challenge/<token>`. The CA connects to
the client's current leased IPv4 address on **TCP port 80**. Permit that
connection from the infrastructure server and keep the challenge path available
for renewal. This callback uses the client's HTTP listener, independently of
the gateway's own HTTP listener. The ACME API continues to use HTTPS on the
gateway.

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

Account and order creation requires an active DHCP lease for the connection's
source address. Each DHCP client may create 8 accounts per rolling 24 hours and
32 orders per rolling hour, across all its account keys. Each account may create
32 orders per rolling 24 hours and have at most 32 outstanding orders. These
limits survive restarts; a `429` response includes `Retry-After`. Invalid orders
and their authorizations are removed immediately, and their creation still
counts toward the limits. Accounts expire after 30 idle days once no retained
orders or certificates reference them. Cleanup runs at startup and on mutations.
Clients whose accounts have expired must register again.

Certificates can be revoked using the issuing account, the certificate's private
key, or an active account with valid HTTP-01 authorizations for every certificate
hostname that still match the current DHCP leases. Signed revocation lists are available
at `https://gateway.home.arpa/acme/crl`, also recorded in issued certificates'
CRL distribution points. Applications must explicitly check the CRL for
revocation to take effect; there is no OCSP responder. This version supports
HTTP-01 only, with no DNS-01 or TLS-ALPN-01 challenge support.

### NFS shares

Add an optional `nfs` array to the existing top-level JSON object:

```json
"nfs": [
  { "share": "data", "path": "/var/data", "read_only": false },
  { "share": "software", "path": "/srv/software", "read_only": true }
]
```

Each `share` names a directory directly below the NFS root. Names are unique,
case-sensitive, and contain 1–255 ASCII letters, digits, underscores, dots, or
hyphens, starting with a letter, digit, or underscore. `path` must be an absolute,
existing directory. `read_only` is a JSON boolean and defaults to `false`.
Omitting `nfs` or setting it to `[]` disables the listener. No rpcbind, mountd,
kernel NFS server, or additional server process is required.

Export paths must not overlap, including aliases through symlinks, and must not
expose configuration, lease state, ACME state, or the private CA directory.
File operations are confined with Go's `os.Root`; symlinks cannot escape an
export. Regular files and directories are supported. Creation of symbolic links,
hard links, and special files is disabled. Read-only shares reject creation,
writes, truncation, removal, renaming, and permission changes on the server,
even when a client attempts to mount them read-write.

For example, on a Linux client with NFS client tools installed:

```sh
sudo mkdir -p /mnt/data /mnt/software
sudo mount -t nfs -o vers=4.0,proto=tcp,sec=none 192.168.50.2:/data /mnt/data
sudo mount -t nfs -o vers=4.0,proto=tcp,sec=none,ro 192.168.50.2:/software /mnt/software
```

This service uses the experimental
[smallfz/libnfs-go](https://github.com/smallfz/libnfs-go) NFSv4.0 implementation.
Use it on a trusted network: traffic is unencrypted, all clients have access to
all configured shares, and filesystem operations run as the server's OS user.
AUTH_NONE and AUTH_SYS requests are accepted; client UID/GID values do not
impersonate OS users, and LDAP accounts do not control NFS access. Restrict TCP
2049 to the intended clients.

This initial implementation supports basic file and directory I/O and size/mode
changes, with a 1 MiB I/O limit. NFSv4.1/4.2, Kerberos, ACLs, ownership/time
changes, locking, delegations, exclusive-create verifiers, and share-deny modes
are unsupported. Open state is scoped to a TCP connection and filehandles are
in memory; reconnecting or restarting can require remounting. It is unsuitable
for applications requiring persistent lock/state recovery. The adapter bounds
connections (64), open files (256 per connection), and filehandles (65,536 per
server run), closes idle connections after five minutes, and stops compounds
at their first failing operation.

### LDAP users and groups

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

## Contributing

Build with `make build` and run the checks below before submitting a change.
For changes to DHCP, DNS, or lease behavior, all three commands are required.
Network tests must use loopback sockets or in-memory connections without
serving the host LAN. The explicit QEMU suite below is an exception and uses
only a disconnected network namespace.

```sh
go test -race ./...
go test -race -tags=integration ./...
go vet ./...
```

Unit tests exercise lease allocation, DHCP packet handling, DNS answers,
certificate generation and renewal, public CA downloads, configuration
validation, PXE architecture selection, LDAP authentication and directory access, plus ACME signed requests
and HTTP-01 validation policy.
Integration tests use local sockets on unprivileged
ports, so they can run without root or changing your network configuration.
HTTPS tests trust only their generated private root and verify the real TLS
handshake and certificate downloads.
LDAP integration tests use loopback sockets and an independent LDAP client to
exercise binds, searches, group membership, and access restrictions.
TFTP integration tests exercise real loopback transfers, option negotiation,
retransmission, built-in file restrictions, transfer limits, and shutdown. An independent
curl interoperability test runs when curl with TFTP support is installed.
NFS tests cover real loopback RPC reads/writes, read-only enforcement, compound
failures, shutdown, path confinement, and stale filehandles without kernel mounts.
An additional Linux kernel-client test verifies mounting, file reads/writes,
renaming, directory creation/removal, and read-only shares. Run it explicitly in
a disposable mount/network namespace (requires `sudo`, `unshare`, `ip`, and the
Linux NFS client module):

```sh
nfs_test_binary=$(mktemp /tmp/infra-box-nfs-test.XXXXXX)
go test -race -c -tags=integration -o "$nfs_test_binary" ./internal/nfsserver
sudo unshare --mount --net sh -c '
  mount --make-rprivate / && ip link set lo up &&
  INFRA_BOX_NFS_KERNEL_TEST=1 "$1" -test.run TestNFSKernelMount -test.v -test.timeout=45s
' sh "$nfs_test_binary"
rm -f "$nfs_test_binary"
```

This opt-in test uses only loopback and refuses to run in the initial mount
namespace or on a network containing any other interface.

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

### QEMU end-to-end test

On an x86-64 Linux host, install the prerequisites and run:

```sh
sudo apt-get install qemu-system-x86 ovmf ipxe-qemu iproute2 tcpdump dnsutils cpio curl
make e2e-qemu
```

This requires Go, Python 3, `/dev/net/tun`, and sudo permission to create network
namespaces and TAP interfaces. The target downloads a checksum-pinned Alpine
3.23.3 netboot archive (about 364 MiB) into `.cache/e2e-qemu`, builds the server
with the race detector, and builds a static Go test probe for the guest. The
guest uses Alpine's kernel, BusyBox DHCP client, and virtio drivers, with a small
test-specific init script. No packages are installed or downloaded in the guest.

The harness runs BIOS and x86-64 UEFI network boots in sequence. Each starts the
complete server and a QEMU guest in a fresh network namespace containing only
loopback and `tap0`. The server uses
`192.168.77.1/24`; the guest obtains its address from DHCP. There is no physical
interface, host bridge, uplink, default gateway, or DNS forwarder. QEMU uses
software emulation so the same test works on GitHub runners without KVM. UEFI
uses OVMF with fresh variables and Secure Boot disabled. Firmware and Linux can
use different DHCP client IDs; the checks follow Linux's assigned lease address.

The BIOS guest downloads the application's embedded `pxelinux.0` over TFTP, and
the UEFI guest downloads its embedded `bootx64.efi`. Both execute iPXE, which uses
the DHCP `next-server` address to fetch `/boot/boot.ipxe`, then downloads the
Alpine kernel and test initramfs over HTTP. The harness compares the captured
TFTP payload against the embedded loader and verifies the HTTP downloads. A
unique value passed by `boot.ipxe` to the guest proves that the script ran.

Each guest verifies DHCP address, subnet, DNS and search-domain options; forward
and reverse DNS over UDP and TCP; short-name resolution; HTTPS with the generated
CA; ACME certificate issuance with a real port-80 HTTP-01 callback; and LDAP/LDAPS
authentication and searches, including rejection of an incorrect password.
The public CA is supplied through the guest initramfs, and TLS verification
remains enabled.

The harness checks that renewal advances the persisted lease expiration, pauses
the DHCP client while restarting the server to verify lease restoration, and
runs the guest service checks again. Finally it verifies that release and actual
lease expiration remove forward and reverse DNS records. A one-minute lease
keeps this test reasonably short. Serial-console checkpoints and bounded waits
make failures observable even when guest networking is broken.

Each run writes `guest.log`, `server.log`, `tcpdump.log`, and `network.pcap` in
separate `bios/` and `uefi/` directories under `artifacts/e2e-qemu/<run-id>/`.
Successful cases also write `boot-proof.json` with the loader and HTTP request
verification. On failure, the harness saves `guest-screen.ppm` when QEMU is
still running, so firmware errors are visible even before the serial console
starts. Temporary guest files, server state, processes, and
the network namespaces are removed on exit, including ordinary failures and
interrupts. Private CA keys are not retained in the artifacts. GitHub Actions
runs `make e2e-qemu` in its own job on every push, pull request, and manual run,
and uploads the diagnostics for seven days even when the test fails. This suite
is separate from `make check` because it needs network administration privileges.

## License

Licensed under the [Apache License 2.0](LICENSE).
