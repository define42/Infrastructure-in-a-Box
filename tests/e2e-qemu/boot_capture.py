"""Verify the network boot chain using the isolated test network's packet capture."""

import hashlib
import math
from pathlib import Path
import struct


SERVER = b"\xc0\xa8\x4d\x01"  # 192.168.77.1
CLIENT = b"\xc0\xa8\x4d\x64"  # 192.168.77.100
GUEST_MAC = b"\x52\x54\x00\x12\x34\x01"
BOOT_PATHS = {"/boot/boot.ipxe", "/boot/vmlinuz", "/boot/initramfs.gz"}


def _address_text(address):
    return ".".join(str(part) for part in address)


def _packets(path):
    """Yield complete Ethernet frames from classic tcpdump pcap, without dependencies."""
    with Path(path).open("rb") as capture:
        header = capture.read(24)
        byte_orders = {
            b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
            b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">",
        }
        if len(header) != 24 or header[:4] not in byte_orders:
            raise RuntimeError("boot capture is not a complete classic pcap file")
        order = byte_orders[header[:4]]
        if struct.unpack_from(order + "I", header, 20)[0] != 1:
            raise RuntimeError("boot capture must contain Ethernet packets")
        for _ in range(4_000_000):
            record = capture.read(16)
            if not record:
                return
            if len(record) != 16:
                raise RuntimeError("boot capture has a truncated packet header")
            captured, original = struct.unpack_from(order + "II", record, 8)
            if captured > 262_144 or captured != original:
                raise RuntimeError("boot capture has an oversized or truncated packet; use tcpdump -s 0")
            frame = capture.read(captured)
            if len(frame) != captured:
                raise RuntimeError("boot capture has a truncated packet")
            yield frame
        raise RuntimeError("boot capture exceeds the packet limit")


def _ipv4(frame):
    if len(frame) < 14:
        return None
    kind = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while kind in (0x8100, 0x88A8):
        if len(frame) < offset + 4:
            return None
        kind = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    if kind != 0x0800 or len(frame) < offset + 20:
        return None
    packet = frame[offset:]
    length = struct.unpack_from("!H", packet, 2)[0]
    header_length = (packet[0] & 15) * 4
    if packet[0] >> 4 != 4 or header_length < 20 or not header_length <= length <= len(packet):
        raise RuntimeError("boot capture contains a malformed IPv4 packet")
    if struct.unpack_from("!H", packet, 6)[0] & 0x3FFF:
        raise RuntimeError("boot capture contains fragmented IPv4; boot transfers should fit the TAP MTU")
    return packet[12:16], packet[16:20], packet[9], packet[header_length:length]


def _dhcp_options(payload):
    options = {}
    position = 240
    while position < len(payload):
        key = payload[position]
        position += 1
        if key == 255:
            break
        if key == 0:
            continue
        if position == len(payload) or position + 1 + payload[position] > len(payload):
            raise RuntimeError("boot capture contains malformed DHCP options")
        length = payload[position]
        options[key] = options.get(key, b"") + payload[position + 1:position + 1 + length]
        position += 1 + length
    return options


class _Transfer:
    def __init__(self):
        self.server_port = None
        self.block_size = 512
        self.blocks = {}
        self.last_block = None
        self.error = None

    def receive(self, port, payload, expected):
        if len(payload) < 2:
            return
        opcode = struct.unpack_from("!H", payload)[0]
        if opcode not in (3, 5, 6):
            return
        if self.server_port is None:
            self.server_port = port
        if self.server_port != port:
            return
        if opcode == 5:
            self.error = payload[4:].rstrip(b"\0").decode("ascii", "replace")
            return
        if opcode == 6:
            fields = payload[2:].rstrip(b"\0").split(b"\0")
            if len(fields) % 2:
                raise RuntimeError("boot capture contains malformed TFTP option acknowledgement")
            options = dict(zip(fields[::2], fields[1::2]))
            try:
                block_size = int(options.get(b"blksize", b"512"))
            except ValueError as error:
                raise RuntimeError("boot capture has an invalid TFTP block size") from error
            if not 8 <= block_size <= 65_464:
                raise RuntimeError("boot capture has an out-of-range TFTP block size")
            if self.blocks and block_size != self.block_size:
                raise RuntimeError("TFTP block size changed during the transfer")
            self.block_size = block_size
            return
        if len(payload) < 4 or len(payload) - 4 > self.block_size:
            raise RuntimeError("boot capture contains malformed TFTP data")
        block = struct.unpack_from("!H", payload, 2)[0]
        # The embedded loaders are small enough that normal PXE block sizes do
        # not wrap. Reject unsupported captures instead of claiming false proof.
        if math.ceil(len(expected) / self.block_size) >= 65_535:
            raise RuntimeError("TFTP capture verification requires a block size that avoids block-number rollover")
        if not 1 <= block <= len(expected) // self.block_size + 1:
            raise RuntimeError("TFTP transfer exceeds the embedded loader size")
        data = payload[4:]
        if block in self.blocks and self.blocks[block] != data:
            raise RuntimeError("TFTP retransmission changed the loader bytes")
        self.blocks[block] = data
        if len(data) < self.block_size:
            self.last_block = block

    def contents(self):
        if self.last_block is None or len(self.blocks) != self.last_block:
            return None
        if any(index not in self.blocks for index in range(1, self.last_block + 1)):
            return None
        return b"".join(self.blocks[index] for index in range(1, self.last_block + 1))


class _HTTPFlow:
    def __init__(self, sequence):
        self.sequence = sequence
        self.data = bytearray(65_536)
        self.present = bytearray(65_536)
        self.length = 0

    def receive(self, sequence, payload):
        offset = (sequence - self.sequence) & 0xFFFFFFFF
        if offset + len(payload) > len(self.data):
            raise RuntimeError("HTTP request stream exceeds boot capture verification limit")
        for index, value in enumerate(payload, offset):
            if self.present[index] and self.data[index] != value:
                raise RuntimeError("HTTP retransmission changed request bytes")
            self.data[index] = value
            self.present[index] = 1
        self.length = max(self.length, offset + len(payload))

    def paths(self):
        # A request line alone in a segment is insufficient: require complete
        # contiguous headers, including when the request was split over packets.
        end = self.present.find(0, 0, self.length)
        if end == -1:
            end = self.length
        headers = bytes(self.data[:end]).split(b"\r\n\r\n")[:-1]
        return {
            fields[1].decode("ascii", "replace")
            for header in headers
            if len(fields := header.split(b"\r\n", 1)[0].split(b" ")) == 3
            and fields[0] == b"GET" and fields[2].startswith(b"HTTP/1.")
        }


def verify_boot_capture(pcap_path, mode, loader_path):
    """Assert DHCP, complete embedded-loader transfer and all HTTP boot requests."""
    if mode not in ("bios", "uefi"):
        raise ValueError(f"unsupported boot mode: {mode}")
    loader = Path(loader_path).read_bytes()
    if not loader or len(loader) > 16 * 1024 * 1024:
        raise ValueError("embedded loader must be nonempty and at most 16 MiB")
    filename = b"pxelinux.0" if mode == "bios" else b"bootx64.efi"
    architectures = {0} if mode == "bios" else {7, 9}
    requests, replies, transfers, http = {}, [], {}, {}
    guest_requests, client_addresses = set(), set()
    complete = None
    http_paths = set()
    for frame in _packets(pcap_path):
        packet = _ipv4(frame)
        if packet is None:
            continue
        source, destination, protocol, payload = packet
        if protocol == 17 and len(payload) >= 8:
            source_port, destination_port, length = struct.unpack_from("!HHH", payload)
            if not 8 <= length <= len(payload):
                raise RuntimeError("boot capture contains a malformed UDP packet")
            data = payload[8:length]
            if (source_port, destination_port) in ((68, 67), (67, 68)):
                if len(data) < 240 or data[236:240] != b"\x63\x82\x53\x63":
                    continue
                if data[1:3] != b"\x01\x06" or data[28:34] != GUEST_MAC:
                    continue
                options = _dhcp_options(data)
                identity = (data[4:8], data[28:34])
                if source_port == 68 and data[0] == 1 and options.get(53) in (b"\x01", b"\x03"):
                    guest_requests.add(identity)
                    arch = options.get(93, b"")
                    if len(arch) % 2 == 0:
                        for index in range(0, len(arch), 2):
                            value = struct.unpack_from("!H", arch, index)[0]
                            if value in architectures:
                                requests[identity] = value
                elif source == SERVER and data[0] == 2 and options.get(53) in (b"\x02", b"\x05"):
                    assigned = data[16:20]
                    if identity not in guest_requests or assigned[:3] != SERVER[:3] or not 100 <= assigned[3] <= 110:
                        continue
                    # Firmware and the embedded iPXE loader may use different
                    # DHCP client IDs and receive separate leases for this MAC.
                    client_addresses.add(assigned)
                    boot_file = options.get(67, data[108:236]).split(b"\0", 1)[0]
                    if data[20:24] == SERVER and boot_file == filename:
                        replies.append(identity)
                if len(guest_requests) > 4096 or len(replies) > 4096:
                    raise RuntimeError("too many DHCP exchanges in boot capture")
                continue
            if source in client_addresses and destination == SERVER and destination_port == 69 and data[:2] == b"\0\x01":
                if data[2:].split(b"\0", 1)[0] == filename:
                    if len(transfers) >= 128:
                        raise RuntimeError("too many TFTP transfers in boot capture")
                    transfers[source, source_port] = _Transfer()
            elif source == SERVER and (destination, destination_port) in transfers:
                transfer = transfers[destination, destination_port]
                transfer.receive(source_port, data, loader)
                contents = transfer.contents()
                if contents is not None:
                    if contents != loader:
                        raise RuntimeError(f"TFTP served bytes different from embedded {filename.decode()}")
                    complete = {"file": filename.decode(), "bytes": len(contents),
                                "sha256": hashlib.sha256(contents).hexdigest(),
                                "block_size": transfer.block_size,
                                "client_address": _address_text(destination)}
        elif protocol == 6 and source in client_addresses and destination == SERVER and len(payload) >= 20:
            source_port, destination_port, sequence = struct.unpack_from("!HHI", payload)
            if destination_port != 80:
                continue
            offset = (payload[12] >> 4) * 4
            if not 20 <= offset <= len(payload):
                raise RuntimeError("boot capture contains malformed TCP headers")
            syn = bool(payload[13] & 2)
            data = payload[offset:]
            identity = (source, source_port)
            if syn:
                if identity in http:
                    http_paths.update(http[identity].paths())
                http[identity] = _HTTPFlow((sequence + 1) & 0xFFFFFFFF)
            if data:
                if identity not in http:
                    http[identity] = _HTTPFlow(sequence)
                http[identity].receive((sequence + int(syn)) & 0xFFFFFFFF, data)
            if len(http) > 1024:
                raise RuntimeError("too many HTTP connections in boot capture")
    matched = [requests[identity] for identity in replies if identity in requests]
    if not requests:
        raise RuntimeError(f"no {mode} PXE DHCP request with option 93 in boot capture")
    if not matched:
        raise RuntimeError(f"no matching DHCP reply advertising {filename.decode()} and next-server 192.168.77.1")
    if complete is None:
        errors = [transfer.error for transfer in transfers.values() if transfer.error]
        raise RuntimeError(f"no complete TFTP transfer of embedded {filename.decode()}; TFTP errors: {errors}")
    for flow in http.values():
        http_paths.update(flow.paths())
    missing = BOOT_PATHS - http_paths
    if missing:
        raise RuntimeError(f"missing boot HTTP GET requests to 192.168.77.1:80: {sorted(missing)}")
    return {"mode": mode, "dhcp": {"architecture": matched[0], "boot_file": filename.decode(),
                                   "next_server": "192.168.77.1",
                                   "client_addresses": [_address_text(address) for address in sorted(client_addresses)]},
            "tftp": complete, "http_gets": sorted(BOOT_PATHS)}
