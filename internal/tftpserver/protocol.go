package tftpserver

import (
	"bytes"
	"encoding/binary"
	"io/fs"
	"strconv"
	"strings"
	"time"
)

const (
	opRead             = 1
	opWrite            = 2
	opData             = 3
	opAck              = 4
	opError            = 5
	opOptionAck        = 6
	maxRequestSize     = 512
	defaultBlockSize   = 512
	maxBlockSize       = 1468 // Fit DATA in a 1500-byte IPv4 UDP datagram.
	defaultTimeout     = 3 * time.Second
	maxAttempts        = 5
	maxTransferTime    = 10 * time.Minute
	maxTransfers       = 64
	maxClientTransfers = 4
)

type protocolError struct {
	code    uint16
	message string
}

func (e *protocolError) Error() string { return e.message }

type readRequest struct {
	filename  string
	blockSize int
	timeout   time.Duration
	options   []string
}

// RFCs 1350 and 2347: filename, mode and option pairs are NUL-terminated.
func parseRequest(packet []byte) (readRequest, *protocolError) {
	r := readRequest{blockSize: defaultBlockSize, timeout: defaultTimeout}
	if len(packet) < 4 || len(packet) > maxRequestSize || packet[len(packet)-1] != 0 {
		return r, &protocolError{4, "malformed request"}
	}
	if binary.BigEndian.Uint16(packet) != opRead {
		return r, &protocolError{4, "expected read request"}
	}
	fields := bytes.Split(packet[2:len(packet)-1], []byte{0})
	if len(fields) < 2 || len(fields)%2 != 0 {
		return r, &protocolError{4, "malformed request fields"}
	}
	r.filename = string(fields[0])
	if !fs.ValidPath(r.filename) || r.filename == "." || strings.Contains(r.filename, "\\") {
		return r, &protocolError{2, "filename must be a relative path beneath the TFTP root"}
	}
	if !strings.EqualFold(string(fields[1]), "octet") {
		return r, &protocolError{4, "only octet mode is supported"}
	}
	seen := make(map[string]bool)
	for i := 2; i < len(fields); i += 2 {
		key, value := strings.ToLower(string(fields[i])), string(fields[i+1])
		if key == "" || value == "" || seen[key] {
			return r, &protocolError{8, "invalid or duplicate option"}
		}
		seen[key] = true
		switch key {
		case "blksize":
			n, err := strconv.ParseUint(value, 10, 16)
			if err != nil || n < 8 || n > 65464 {
				return r, &protocolError{8, "invalid blksize"}
			}
			r.blockSize = min(int(n), maxBlockSize)
			r.options = append(r.options, key, strconv.Itoa(r.blockSize))
		case "timeout":
			n, err := strconv.ParseUint(value, 10, 8)
			if err != nil || n == 0 {
				return r, &protocolError{8, "invalid timeout"}
			}
			r.timeout = time.Duration(n) * time.Second
			r.options = append(r.options, key, value)
		case "tsize":
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil || n != 0 {
				return r, &protocolError{8, "read tsize must be zero"}
			}
			r.options = append(r.options, key, "0")
		}
		// Unrecognized options are omitted, as required by RFC 2347.
	}
	return r, nil
}

func (r readRequest) optionAck(size int64) []byte {
	if len(r.options) == 0 {
		return nil
	}
	packet := []byte{0, opOptionAck}
	for i := 0; i < len(r.options); i += 2 {
		value := r.options[i+1]
		if r.options[i] == "tsize" {
			value = strconv.FormatInt(size, 10)
		}
		packet = append(packet, r.options[i]...)
		packet = append(packet, 0)
		packet = append(packet, value...)
		packet = append(packet, 0)
	}
	return packet
}

func errorPacket(code uint16, message string) []byte {
	packet := make([]byte, 4, 5+len(message))
	binary.BigEndian.PutUint16(packet, opError)
	binary.BigEndian.PutUint16(packet[2:], code)
	packet = append(packet, message...)
	return append(packet, 0)
}
