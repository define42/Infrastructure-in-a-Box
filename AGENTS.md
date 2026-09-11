# Go development

Use the `golang-how-to` skill when available for Go coding, review, debugging,
and setup tasks, and apply the relevant Go skills it identifies.

Run `go test -race ./...`, `go test -race -tags=integration ./...`, and
`go vet ./...` for changes to DHCP, DNS, or lease behavior. Network tests must
use loopback sockets or in-memory connections without serving the host LAN.
The explicit `make e2e-qemu` suite is an exception: it may use TAP interfaces
inside a disposable network namespace with no uplink or host LAN connection.
