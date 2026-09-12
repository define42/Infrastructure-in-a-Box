"""Synthetic packet captures exercise the evidence required by the QEMU suite."""

import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from boot_capture import CLIENT, GUEST_MAC, SERVER, verify_boot_capture


def ipv4(protocol, source, destination, payload):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0,
                         64, protocol, 0, source, destination)
    return bytes(12) + b"\x08\x00" + header + payload


def udp(source, destination, source_port, destination_port, payload):
    header = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
    return ipv4(17, source, destination, header + payload)


def tcp(sequence, payload, flags=0x18, client=CLIENT):
    header = struct.pack("!HHIIBBHHH", 10000, 80, sequence, 0, 0x50, flags, 65535, 0, 0)
    return ipv4(6, client, SERVER, header + payload)


def dhcp(architecture, filename, wrong_next_server=False, client=CLIENT,
         mac=GUEST_MAC, transaction=b"\x12\x34\x56\x78"):
    request = bytearray(240)
    request[:3] = b"\x01\x01\x06"
    request[4:8] = transaction
    request[28:34] = mac
    request[236:240] = b"\x63\x82\x53\x63"
    reply = request.copy()
    reply[0] = 2
    reply[16:20] = client
    reply[20:24] = CLIENT if wrong_next_server else SERVER
    request += b"\x35\x01\x01\x5d\x02" + struct.pack("!H", architecture) + b"\xff"
    reply += b"\x35\x01\x02\x43" + bytes([len(filename)]) + filename + b"\xff"
    return [udp(bytes(4), b"\xff" * 4, 68, 67, request),
            udp(SERVER, b"\xff" * 4, 67, 68, reply)]


def transfer(filename, loader, block_size, skip_block=None, corrupt=False, client=CLIENT):
    packets = [udp(client, SERVER, 1234, 69, b"\0\x01" + filename + b"\0octet\0")]
    if block_size != 512:
        packets.append(udp(SERVER, client, 4321, 1234,
                           b"\0\x06blksize\0" + str(block_size).encode() + b"\0tsize\0" +
                           str(len(loader)).encode() + b"\0"))
    for block, start in enumerate(range(0, len(loader) + 1, block_size), 1):
        if block == skip_block:
            continue
        content = loader[start:start + block_size]
        if corrupt and block == 1:
            content = b"!" + content[1:]
        packet = udp(SERVER, client, 4321, 1234, struct.pack("!HH", 3, block) + content)
        packets.extend([packet, packet])  # Identical retransmissions are legal.
    return packets


def http(paths, client=CLIENT):
    packets = [tcp(999, b"", flags=2, client=client)]
    sequence = 1000
    for path in paths:
        request = f"GET {path} HTTP/1.1\r\nHost: 192.168.77.1\r\n\r\n".encode()
        # Deliver a request split in the URL, with reordering and retransmission.
        packets.extend([tcp(sequence + 13, request[13:], client=client),
                        tcp(sequence, request[:13], client=client),
                        tcp(sequence, request[:13], client=client)])
        sequence += len(request)
    return packets


def pcap(packets, order="<"):
    data = struct.pack(order + "IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    for packet in packets:
        data += struct.pack(order + "IIII", 0, 0, len(packet), len(packet)) + packet
    return data


class BootCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.loader = bytes(range(256)) * 6
        self.loader_path = self.root / "loader"
        self.loader_path.write_bytes(self.loader)

    def verify(self, packets, mode="bios", order="<"):
        path = self.root / "network.pcap"
        path.write_bytes(pcap(packets, order))
        return verify_boot_capture(path, mode, self.loader_path)

    def packets(self, mode="bios", architecture=None, block_size=512,
                skip_block=None, corrupt=False, wrong_next_server=False, paths=None):
        filename = b"pxelinux.0" if mode == "bios" else b"bootx64.efi"
        if architecture is None:
            architecture = 0 if mode == "bios" else 9
        if paths is None:
            paths = ["/boot/boot.ipxe", "/boot/vmlinuz", "/boot/initramfs.gz"]
        return (dhcp(architecture, filename, wrong_next_server) +
                transfer(filename, self.loader, block_size, skip_block, corrupt) + http(paths))

    def test_bios_and_uefi_boot_evidence(self):
        for mode, architecture, block_size, order in [
            ("bios", 0, 512, "<"),  # Also requires the final empty TFTP block.
            ("uefi", 7, 1024, ">"),
            ("uefi", 9, 1468, "<"),
        ]:
            with self.subTest(mode=mode, architecture=architecture):
                summary = self.verify(self.packets(mode, architecture, block_size), mode, order)
                self.assertEqual(summary["dhcp"]["architecture"], architecture)
                self.assertEqual(summary["tftp"]["bytes"], len(self.loader))
                self.assertEqual(summary["tftp"]["sha256"], hashlib.sha256(self.loader).hexdigest())
                self.assertEqual(summary["tftp"]["block_size"], block_size)

    def test_requires_correct_pxe_architecture(self):
        with self.assertRaisesRegex(RuntimeError, "no bios PXE DHCP request with option 93"):
            self.verify(self.packets(architecture=9))

    def test_firmware_and_ipxe_can_receive_separate_leases(self):
        ipxe_address = b"\xc0\xa8\x4d\x65"
        packets = (dhcp(7, b"bootx64.efi") + transfer(b"bootx64.efi", self.loader, 1024) +
                   dhcp(7, b"bootx64.efi", client=ipxe_address, transaction=b"\x87\x65\x43\x21") +
                   http(["/boot/boot.ipxe", "/boot/vmlinuz", "/boot/initramfs.gz"], client=ipxe_address))
        summary = self.verify(packets, mode="uefi")
        self.assertEqual(summary["dhcp"]["client_addresses"], ["192.168.77.100", "192.168.77.101"])
        self.assertEqual(summary["tftp"]["client_address"], "192.168.77.100")

    def test_rejects_http_from_another_guest_or_unmatched_assignment(self):
        address = b"\xc0\xa8\x4d\x65"
        for reason, extra in [
            ("different MAC", dhcp(0, b"pxelinux.0", client=address, mac=b"\x52\x54\x00\x12\x34\x02")),
            ("unmatched reply", dhcp(0, b"pxelinux.0", client=address, transaction=b"\0\0\0\x01")[1:]),
            ("no assignment", []),
        ]:
            with self.subTest(reason=reason):
                packets = (dhcp(0, b"pxelinux.0") + transfer(b"pxelinux.0", self.loader, 512) + extra +
                           http(["/boot/boot.ipxe", "/boot/vmlinuz", "/boot/initramfs.gz"], client=address))
                with self.assertRaisesRegex(RuntimeError, "missing boot HTTP GET requests"):
                    self.verify(packets)

    def test_rejects_assignment_outside_isolated_pool(self):
        address = b"\xc0\xa8\x4d\x6f"
        packets = (dhcp(0, b"pxelinux.0", client=address) +
                   transfer(b"pxelinux.0", self.loader, 512, client=address) +
                   http(["/boot/boot.ipxe", "/boot/vmlinuz", "/boot/initramfs.gz"], client=address))
        with self.assertRaisesRegex(RuntimeError, "no matching DHCP reply"):
            self.verify(packets)

    def test_requires_matching_reply_next_server(self):
        with self.assertRaisesRegex(RuntimeError, "no matching DHCP reply"):
            self.verify(self.packets(wrong_next_server=True))

    def test_rejects_missing_tftp_data(self):
        with self.assertRaisesRegex(RuntimeError, "no complete TFTP transfer"):
            self.verify(self.packets(skip_block=2))

    def test_rejects_missing_terminal_empty_tftp_block(self):
        with self.assertRaisesRegex(RuntimeError, "no complete TFTP transfer"):
            self.verify(self.packets(skip_block=4))

    def test_rejects_wrong_loader_contents(self):
        with self.assertRaisesRegex(RuntimeError, "different from embedded pxelinux.0"):
            self.verify(self.packets(corrupt=True))

    def test_requires_boot_script_http_request(self):
        with self.assertRaisesRegex(RuntimeError, "missing boot HTTP GET requests.*boot.ipxe"):
            self.verify(self.packets(paths=["/boot/vmlinuz", "/boot/initramfs.gz"]))

    def test_rejects_truncated_capture(self):
        path = self.root / "network.pcap"
        path.write_bytes(pcap(self.packets())[:-1])
        with self.assertRaisesRegex(RuntimeError, "truncated packet"):
            verify_boot_capture(path, "bios", self.loader_path)


if __name__ == "__main__":
    unittest.main()
