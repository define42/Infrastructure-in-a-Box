#!/usr/bin/env python3
"""Run the real server and an Alpine DHCP client on a disconnected TAP network."""

import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid


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


def run(artifacts):
    namespace = "infra-e2e-" + uuid.uuid4().hex[:10]
    processes = []
    files = []
    created = False
    prefix = ["ip", "netns", "exec", namespace]

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
        config = {
            "interface": "tap0", "server_ip": "192.168.77.1",
            "subnet": "192.168.77.0/24", "pool_start": "192.168.77.100",
            "pool_end": "192.168.77.110", "router": "", "upstream": "",
            "domain": "home.arpa", "lease_duration": "1m", "dns_ttl": "1s",
            "lease_file": "leases.json", "ca_dir": "pki",
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
            if len(leases) != 1 or leases[0]["ip"] != "192.168.77.100":
                raise RuntimeError(f"unexpected persisted leases: {leases}")
            return leases[0]

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
                ["tcpdump", "-i", "tap0", "-U", "-n", "-Z", "root", "-w", str(artifacts / "network.pcap")],
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
            names = b"\0".join(os.fsencode(str(path.relative_to(root))) for path in sorted(root.rglob("*"))) + b"\0"
            archive = command("cpio", "--null", "-o", "-H", "newc", "--quiet", cwd=root, input=names, capture_output=True).stdout
            initramfs = work / "initramfs.gz"
            with gzip.open(initramfs, "wb") as output:
                output.write(archive)
            guest = spawn([
                "qemu-system-x86_64", "-machine", "q35", "-accel", "tcg",
                "-m", "512", "-smp", "2", "-no-reboot", "-display", "none",
                "-monitor", "none", "-serial", "stdio",
                "-kernel", str(ASSETS / "boot/vmlinuz-virt"), "-initrd", str(initramfs),
                "-append", "console=ttyS0 panic=1 quiet",
                "-netdev", "tap,id=lab,ifname=tap0,script=no,downscript=no",
                "-device", "virtio-net-pci,netdev=lab,mac=52:54:00:12:34:01",
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
                print(f"PASS: {name}", flush=True)

            def resume():
                guest.stdin.write(b"continue\n")
                guest.stdin.flush()

            stage("BOUND")
            initial = lease()
            resume()
            stage("RENEWED")
            renewed = lease()
            if renewed["expires_at"] <= initial["expires_at"]:
                raise RuntimeError("renewal did not advance persisted expiration")
            resume()
            stage("RESTART")
            before_restart = lease()
            stop(server)
            if server.returncode != 0:
                raise RuntimeError(f"server shutdown failed: {server.returncode}")
            server = start_server()
            if lease() != before_restart or dns("client1.home.arpa") != "192.168.77.100":
                raise RuntimeError("restart did not preserve lease and DNS")
            resume()
            stage("RELEASED")

            def records_absent():
                for tcp in (False, True):
                    for name, kind in (("client1.home.arpa", "A"), ("100.77.168.192.in-addr.arpa", "PTR")):
                        result = command(
                            *prefix, "dig", "+time=1", "+tries=1", "+noall", "+comments", "+answer",
                            *(["+tcp"] if tcp else []), "@192.168.77.1", name, kind,
                            capture_output=True, text=True,
                        )
                        # SERVFAIL, REFUSED and a dead server must never count as removal.
                        if "status: NXDOMAIN" not in result.stdout or "ANSWER: 0" not in result.stdout:
                            return False
                return True

            eventually("DNS removal after release", records_absent)
            if json.loads((state / "leases.json").read_text())["leases"]:
                raise RuntimeError("release retained persisted lease")
            resume()
            stage("EXPIRING")
            expiring = lease()
            if dns("client1.home.arpa") != "192.168.77.100":
                raise RuntimeError("reacquired lease missing DNS record")
            expiry = datetime.datetime.fromisoformat(expiring["expires_at"].replace("Z", "+00:00"))
            eventually("lease expiration", lambda: datetime.datetime.now(datetime.timezone.utc) > expiry, 75)
            eventually("DNS removal after expiration", records_absent)
            resume()
            stage("PASS", 15)
            guest.wait(timeout=15)
            if guest.returncode != 0:
                raise RuntimeError(f"QEMU exited with status {guest.returncode}")
            stop(server)
            if server.returncode != 0 or "DATA RACE" in (artifacts / "server.log").read_text():
                raise RuntimeError("server failed or race detector reported an error")
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
    artifacts = REPO / "artifacts/e2e-qemu" / (time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6])
    artifacts.mkdir(parents=True)
    print(f"Artifacts: {artifacts}", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit("test terminated"))
    try:
        run(artifacts)
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr)
        for name in ("server.log", "guest.log", "tcpdump.log"):
            path = artifacts / name
            if path.exists():
                print(f"\n{name}:\n" + "\n".join(path.read_text(errors="replace").splitlines()[-100:]), file=sys.stderr)
        return 1
    finally:
        # Let the invoking user inspect logs; never retain the server's private CA.
        uid = int(os.environ.get("SUDO_UID", os.getuid()))
        gid = int(os.environ.get("SUDO_GID", os.getgid()))
        for path in (artifacts, *artifacts.rglob("*")):
            os.chown(path, uid, gid)
    print("QEMU end-to-end test passed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
