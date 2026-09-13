These iPXE loaders are embedded in the Infrastructure in a Box executable:

- `pxelinux.0`: iPXE's BIOS `undionly.kpxe`, named for our DHCP boot filename.
- `bootx64.efi`: iPXE's unsigned x64 UEFI `ipxe-legacy.efi`.

The UEFI loader keeps native PCI network drivers but leaves USB controllers with
the firmware. This avoids a [USB keyboard compatibility issue](https://github.com/ipxe/ipxe/issues/1643)
in iPXE menus and chained EFI applications. Despite the name, `ipxe-legacy.efi`
is a UEFI loader, not a legacy BIOS loader. It excludes native USB network
drivers, so USB Ethernet adapters may require a different iPXE build.

Both loaders explicitly enable `CONSOLE_CMD`, `CONSOLE_FRAMEBUFFER`, and
`IMAGE_PNG` for graphical menus and PNG backgrounds. JPEG backgrounds are not
supported. Convert pictures to PNG and size them for the requested console mode
(for example, 1024x768); iPXE does not scale pictures to fit. Keep backgrounds in
`boot_root` and load them with `console --picture http://${next-server}/boot/bg.png`.
Handle a failed `console` command with `|| goto menu` so missing pictures or
unsupported display modes still allow the text menu to run.

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
