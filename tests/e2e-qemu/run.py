#!/usr/bin/env python3
"""PXE boot BIOS and UEFI Linux guests through the real server on isolated TAPs."""

import datetime
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

from boot_capture import verify_boot_capture


REPO = Path(__file__).resolve().parents[2]
ASSETS = REPO / ".cache/e2e-qemu"
SCRIPTS = Path(__file__).resolve().parent


def command(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=30, **kwargs)


def eventually(description, predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise RuntimeError(f"timed out: {description}")


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def firmware_paths():
    rom = Path("/usr/lib/ipxe/qemu/pxe-virtio.rom")
    if not rom.is_file():
        sys.exit(f"missing BIOS PXE ROM: {rom}; install ipxe-qemu")
    # Distributions ship ROMs for either transitional (1000) or modern (1041)
    # virtio. SeaBIOS skips a ROM whose PCI ID does not match the emulated NIC.
    header = rom.read_bytes()
    offset = int.from_bytes(header[0x18:0x1A], "little")
    if header[offset:offset + 4] != b"PCIR" or header[offset + 4:offset + 6] != b"\xf4\x1a":
        sys.exit(f"unrecognized virtio PCI ROM: {rom}")
    device = int.from_bytes(header[offset + 6:offset + 8], "little")
    modes = {0x1000: "disable-modern=on", 0x1041: "disable-legacy=on"}
    if device not in modes:
        sys.exit(f"unsupported virtio PCI ROM device: {device:04x}")
    for suffix in ("_4M", ""):
        code = Path(f"/usr/share/OVMF/OVMF_CODE{suffix}.fd")
        variables = Path(f"/usr/share/OVMF/OVMF_VARS{suffix}.fd")
        if code.is_file() and variables.is_file():
            return rom, code, variables, modes[device]
    sys.exit("missing OVMF code/variables firmware pair in /usr/share/OVMF; install ovmf")


def capture_screen(monitor, destination):
    """Keep the firmware's VGA error screen when it cannot reach Linux serial output."""
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(5)
            connection.connect(str(monitor))
            with connection.makefile("rwb") as stream:
                json.loads(stream.readline())  # QMP greeting.
                for request in (
                    {"execute": "qmp_capabilities"},
                    {"execute": "screendump", "arguments": {"filename": str(destination)}},
                ):
                    stream.write(json.dumps(request).encode() + b"\n")
                    stream.flush()
                    while "return" not in (response := json.loads(stream.readline())):
                        if "error" in response:
                            return
    except (OSError, ValueError):
        pass  # The guest may already have exited; retain the original failure.


def run(artifacts, mode, firmware):
    namespace = "infra-e2e-" + uuid.uuid4().hex[:10]
    processes = []
    files = []
    created = False
    prefix = ["ip", "netns", "exec", namespace]
    boot_token = uuid.uuid4().hex

    def spawn(args, logfile, **kwargs):
        log = (artifacts / logfile).open("ab", buffering=0)
        files.append(log)
        process = subprocess.Popen(
            prefix + args, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True, **kwargs,
        )
        processes.append(process)
        return process

    def dns(name, kind="A", tcp=False):
        result = command(
            *prefix, "dig", "+time=1", "+tries=1", "+short",
            *(["+tcp"] if tcp else []), "@192.168.77.1", name, kind,
            capture_output=True, text=True,
        )
        return result.stdout.strip()

    with tempfile.TemporaryDirectory(prefix="infra-e2e-") as temporary:
        work = Path(temporary)
        state = work / "state"
        state.mkdir()
        boot_root = state / "boot"
        boot_root.mkdir()
        monitor = work / "monitor.sock"
        config = {
            "interface": "tap0", "server_ip": "192.168.77.1",
            "subnet": "192.168.77.0/24", "pool_start": "192.168.77.100",
            "pool_end": "192.168.77.110", "router": "", "upstream": "",
            "domain": "home.arpa", "lease_duration": "1m", "dns_ttl": "1s",
            "lease_file": "leases.json", "ca_dir": "pki", "boot_root": "boot",
            "ldap": {
                "users": [{
                    "name": "reader", "primary_group": 5500, "can_search": True,
                    "pass_sha256": hashlib.sha256(b"qemu-test-password").hexdigest(),
                }],
                "groups": [{"name": "readers", "gid": 5500}],
            },
        }
        config_file = state / "config.json"
        config_file.write_text(json.dumps(config))

        def lease():
            leases = json.loads((state / "leases.json").read_text())["leases"]
            # Firmware may retain a separate lease under its own client ID.
            # Follow the Linux guest's named lease rather than a fixed pool slot.
            clients = [item for item in leases if item.get("hostname") == "client1.home.arpa."]
            if len(clients) != 1:
                raise RuntimeError(f"unexpected persisted leases: {leases}")
            current = clients[0]
            if not (ipaddress.ip_address(config["pool_start"]) <= ipaddress.ip_address(current["ip"])
                    <= ipaddress.ip_address(config["pool_end"])):
                raise RuntimeError(f"guest lease outside configured pool: {current}")
            return current

        def start_server():
            process = spawn([str(ASSETS / "infra-box"), "-config", str(config_file)], "server.log")

            def ready():
                if process.poll() is not None:
                    raise RuntimeError("infra-box exited during startup")
                try:
                    return dns("gateway.home.arpa") == "192.168.77.1"
                except subprocess.CalledProcessError:
                    return False

            eventually("server readiness", ready)
            return process

        try:
            command("ip", "netns", "add", namespace)
            created = True
            command("ip", "-n", namespace, "link", "set", "lo", "up")
            command(*prefix, "ip", "tuntap", "add", "dev", "tap0", "mode", "tap")
            command("ip", "-n", namespace, "addr", "add", "192.168.77.1/24", "dev", "tap0")
            command("ip", "-n", namespace, "link", "set", "tap0", "up")
            # No veth uplink, physical NIC, bridge to the host, NAT, or default route.
            links = json.loads(command("ip", "-n", namespace, "-j", "link", "show", capture_output=True).stdout)
            if {link["ifname"] for link in links} != {"lo", "tap0"}:
                raise RuntimeError("unexpected interface in isolated namespace")
            capture = spawn(
                ["tcpdump", "-i", "tap0", "-s", "0", "-B", "16384", "-U", "-n", "-Z", "root",
                 "-w", str(artifacts / "network.pcap")],
                "tcpdump.log",
            )
            eventually("packet capture readiness", lambda: (artifacts / "network.pcap").exists())
            if capture.poll() is not None:
                raise RuntimeError("packet capture failed")
            server = start_server()

            # Reuse Alpine's kernel, BusyBox and virtio modules, replacing only init
            # and adding the test scripts, static Go probe and this run's public CA.
            root = work / "root"
            root.mkdir()
            with gzip.open(ASSETS / "boot/initramfs-virt", "rb") as source:
                command("cpio", "-idm", "--quiet", "--no-absolute-filenames", cwd=root, input=source.read())
            for name in ("init", "dhcp-hook"):
                target = root / name
                target.unlink(missing_ok=True)
                shutil.copyfile(SCRIPTS / name, target)
                target.chmod(0o755)
            shutil.copyfile(ASSETS / "probe", root / "probe")
            (root / "probe").chmod(0o755)
            shutil.copyfile(state / "pki/root-ca.pem", root / "root-ca.pem")
            (root / "boot-token").write_text(boot_token + "\n")
            (root / "boot-mode").write_text(mode + "\n")
            names = b"\0".join(os.fsencode(str(path.relative_to(root))) for path in sorted(root.rglob("*"))) + b"\0"
            archive = command("cpio", "--null", "-o", "-H", "newc", "--quiet", cwd=root, input=names, capture_output=True).stdout
            initramfs = boot_root / "initramfs.gz"
            with gzip.open(initramfs, "wb") as output:
                output.write(archive)
            shutil.copyfile(ASSETS / "boot/vmlinuz-virt", boot_root / "vmlinuz")
            (boot_root / "boot.ipxe").write_text(
                "#!ipxe\n"
                "set base http://${next-server}/boot\n"
                f"kernel ${{base}}/vmlinuz console=ttyS0 panic=1 quiet e2e_boot={boot_token}\n"
                "initrd ${base}/initramfs.gz\n"
                "boot\n"
            )
            rom, code, variables, nic_mode = firmware
            firmware_args = []
            if mode == "bios":
                nic_rom = str(rom)
            else:
                # OVMF's native virtio PXE driver downloads our embedded EFI loader.
                # Each guest gets disposable NVRAM with Secure Boot disabled.
                nic_rom = ""
                nic_mode = "disable-legacy=on"
                nvram = work / "OVMF_VARS.fd"
                shutil.copyfile(variables, nvram)
                firmware_args = [
                    "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
                    "-drive", f"if=pflash,format=raw,unit=1,file={nvram}",
                ]
            guest = spawn([
                "qemu-system-x86_64", "-machine", "q35", "-accel", "tcg",
                "-m", "512", "-smp", "2", "-no-reboot", "-display", "none",
                "-monitor", "none", "-qmp", f"unix:{monitor},server=on,wait=off", "-serial", "stdio",
                *firmware_args,
                "-netdev", "tap,id=lab,ifname=tap0,script=no,downscript=no",
                "-device", f"virtio-net-pci,{nic_mode},netdev=lab,mac=52:54:00:12:34:01,"
                           f"bootindex=1,romfile={nic_rom}",
            ], "guest.log", stdin=subprocess.PIPE)

            def stage(name, seconds=120):
                def reached():
                    output = (artifacts / "guest.log").read_text(errors="replace")
                    if "E2E FAIL:" in output:
                        raise RuntimeError("guest reported failure")
                    if f"E2E {name}\n" in output:
                        return True
                    if guest.poll() is not None or server.poll() is not None:
                        raise RuntimeError(f"server or guest exited before {name}")
                    return False

                eventually(f"guest {name}", reached, seconds)
                print(f"PASS [{mode}]: {name}", flush=True)

            def resume():
                guest.stdin.write(b"continue\n")
                guest.stdin.flush()

            stage(f"BOOT {mode} {boot_token}", 180)
            stage("BOUND")
            initial = lease()
            resume()
            stage("RENEWED")
            renewed = lease()
            if renewed["ip"] != initial["ip"]:
                raise RuntimeError("renewal changed the guest's address")
            if renewed["expires_at"] <= initial["expires_at"]:
                raise RuntimeError("renewal did not advance persisted expiration")
            resume()
            stage("RESTART")
            before_restart = lease()
            stop(server)
            if server.returncode != 0:
                raise RuntimeError(f"server shutdown failed: {server.returncode}")
            server = start_server()
            if lease() != before_restart or dns("client1.home.arpa") != before_restart["ip"]:
                raise RuntimeError("restart did not preserve lease and DNS")
            resume()
            stage("RELEASED")

            def records_absent(address):
                reverse = ipaddress.ip_address(address).reverse_pointer
                for tcp in (False, True):
                    for name, kind in (("client1.home.arpa", "A"), (reverse, "PTR")):
                        result = command(
                            *prefix, "dig", "+time=1", "+tries=1", "+noall", "+comments", "+answer",
                            *(["+tcp"] if tcp else []), "@192.168.77.1", name, kind,
                            capture_output=True, text=True,
                        )
                        # SERVFAIL, REFUSED and a dead server must never count as removal.
                        if "status: NXDOMAIN" not in result.stdout or "ANSWER: 0" not in result.stdout:
                            return False
                return True

            eventually("DNS removal after release", lambda: records_absent(before_restart["ip"]))
            remaining = json.loads((state / "leases.json").read_text())["leases"]
            if any(item["client_id"] == before_restart["client_id"] for item in remaining):
                raise RuntimeError("release retained persisted guest lease")
            resume()
            stage("EXPIRING")
            expiring = lease()
            if dns("client1.home.arpa") != expiring["ip"]:
                raise RuntimeError("reacquired lease missing DNS record")
            expiry = datetime.datetime.fromisoformat(expiring["expires_at"].replace("Z", "+00:00"))
            eventually("lease expiration", lambda: datetime.datetime.now(datetime.timezone.utc) > expiry, 75)
            eventually("DNS removal after expiration", lambda: records_absent(expiring["ip"]))
            resume()
            stage("PASS", 15)
            guest.wait(timeout=15)
            if guest.returncode != 0:
                raise RuntimeError(f"QEMU exited with status {guest.returncode}")
            stop(server)
            if server.returncode != 0 or "DATA RACE" in (artifacts / "server.log").read_text():
                raise RuntimeError("server failed or race detector reported an error")
            stop(capture)
            loader = "pxelinux.0" if mode == "bios" else "bootx64.efi"
            proof = verify_boot_capture(artifacts / "network.pcap", mode, REPO / "ipxe" / loader)
            proof["guest_boot_token"] = boot_token
            (artifacts / "boot-proof.json").write_text(json.dumps(proof, indent=2) + "\n")
            print(f"PASS [{mode}]: captured DHCP, embedded {loader}, and HTTP boot chain", flush=True)
        except Exception:
            capture_screen(monitor, artifacts / "guest-screen.ppm")
            raise
        finally:
            for process in reversed(processes):
                stop(process)
            for file in files:
                file.close()
            if created:
                command("ip", "netns", "delete", namespace)


def main():
    if os.geteuid() != 0:
        sys.exit("run.py requires root for the isolated network namespace; use make e2e-qemu")
    for executable in ("ip", "qemu-system-x86_64", "tcpdump", "dig", "cpio"):
        if shutil.which(executable) is None:
            sys.exit(f"missing dependency: {executable}")
    for asset in ("infra-box", "probe", "boot/vmlinuz-virt", "boot/initramfs-virt"):
        if not (ASSETS / asset).is_file():
            sys.exit(f"missing {asset}; run tests/e2e-qemu/prepare.sh first")
    firmware = firmware_paths()
    artifacts = REPO / "artifacts/e2e-qemu" / (time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6])
    artifacts.mkdir(parents=True)
    print(f"Artifacts: {artifacts}", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit("test terminated"))
    try:
        for mode in ("bios", "uefi"):
            case_artifacts = artifacts / mode
            case_artifacts.mkdir()
            print(f"Booting {mode.upper()} through DHCP, TFTP, and HTTP", flush=True)
            run(case_artifacts, mode, firmware)
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        for name in ("server.log", "guest.log", "tcpdump.log"):
            path = case_artifacts / name
            if path.exists():
                print(f"\n{name}:\n" + "\n".join(path.read_text(errors="replace").splitlines()[-100:]), file=sys.stderr)
        return 1
    finally:
        # Let the invoking user inspect logs; never retain the server's private CA.
        uid = int(os.environ.get("SUDO_UID", os.getuid()))
        gid = int(os.environ.get("SUDO_GID", os.getgid()))
        for path in (artifacts, *artifacts.rglob("*")):
            os.chown(path, uid, gid)
    print("BIOS and UEFI QEMU end-to-end tests passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
