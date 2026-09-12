package ntpserver

import (
	"encoding/binary"
	"time"
)

const packetSize = 48

// response implements the basic NTPv3/v4 client/server exchange from RFC 5905.
// The host clock is deliberately the lab's reference, even without an upstream.
// Stratum 10 and the local-clock reference ID avoid claiming a precision source.
// Only plain, unauthenticated requests are supported; extensions and MACs are
// dropped rather than silently stripping authentication from a reply.
func response(request []byte, received, transmitted time.Time) ([packetSize]byte, bool) {
	var reply [packetSize]byte
	if len(request) != packetSize {
		return reply, false
	}
	version := (request[0] >> 3) & 7
	if (version != 3 && version != 4) || request[0]&7 != 3 {
		return reply, false
	}
	reply[0] = version<<3 | 4 // No leap warning; server mode.
	reply[1] = 10
	reply[2] = request[2] // Echo the client's polling interval.
	reply[3] = 0xf6       // Precision: 2^-10 seconds (about a millisecond).
	// Zero root delay to the host clock; conservatively allow 1 ms dispersion.
	binary.BigEndian.PutUint32(reply[8:12], 66) // Unsigned 16.16 seconds.
	copy(reply[12:16], []byte{127, 127, 1, 0})  // Local reference clock, not UTC.
	putTimestamp(reply[16:24], received)        // Latest host-clock sample.
	copy(reply[24:32], request[40:48])          // Client's transmit becomes origin.
	putTimestamp(reply[32:40], received)
	putTimestamp(reply[40:48], transmitted)
	return reply, true
}

func putTimestamp(dst []byte, t time.Time) {
	const epochOffset = 2_208_988_800 // Seconds from 1900-01-01 to the Unix epoch.
	// Conversion to uint32 intentionally wraps at NTP era boundaries (2036).
	binary.BigEndian.PutUint32(dst[:4], uint32(t.Unix()+epochOffset))
	fraction := (uint64(t.Nanosecond()) << 32) / 1_000_000_000
	binary.BigEndian.PutUint32(dst[4:8], uint32(fraction))
}
