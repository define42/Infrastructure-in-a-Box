These iPXE loaders are embedded in the Infrastructure in a Box executable:

- `pxelinux.0`: iPXE's BIOS `undionly.kpxe`, named for our DHCP boot filename.
- `bootx64.efi`: iPXE's unsigned x64 UEFI `ipxe.efi`.

`../build-ipxe.sh` downloads the [upstream source](https://github.com/ipxe/ipxe),
embeds `bootstrap.ipxe`, and replaces both loaders. `ipxe-revision.txt` records
the source commit. To rebuild that revision from the repository root:

```sh
IPXE_REF="$(cat ipxe/ipxe-revision.txt)" ./build-ipxe.sh
make build
```

The bootstrap obtains DHCP settings and loads the main script from
`http://${next-server}/boot/boot.ipxe`. Keep that main script and operating system
images in the configured `boot_root` directory, which is served over HTTP/HTTPS.

The upstream license notices are included as `COPYING*`. Only `pxelinux.0` and
`bootx64.efi` are embedded and available over TFTP; metadata and source files
in this directory are excluded.
