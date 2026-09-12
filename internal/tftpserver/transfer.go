package tftpserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

func (s *Server) transfer(ctx context.Context, root *os.Root, local *net.UDPAddr, peer netip.AddrPort, request readRequest) error {
	ctx, cancel := context.WithTimeout(ctx, maxTransferTime)
	defer cancel()
	conn, err := net.ListenUDP("udp4", local)
	if err != nil {
		return fmt.Errorf("open TFTP transfer socket: %w", err)
	}
	defer func() { _ = conn.Close() }()
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(stopped) })
	defer func() {
		if !stop() {
			<-stopped
		}
	}()
	// os.Root prevents traversal and symlink escapes, including concurrent
	// renames. Nonblocking open lets us reject FIFOs without hanging shutdown.
	file, err := root.OpenFile(request.filename, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		code := uint16(2)
		if errors.Is(err, os.ErrNotExist) {
			code = 1
		}
		s.sendError(conn, peer, code, "file unavailable")
		return err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		s.sendError(conn, peer, 2, "only regular files can be downloaded")
		return errors.New("TFTP requested a non-regular or unreadable file")
	}
	if packet := request.optionAck(info.Size()); packet != nil {
		if err := exchange(ctx, conn, peer, packet, 0, request.timeout); err != nil {
			return err
		}
	}
	// Limit reads to the announced size even if the file grows during transfer.
	reader := io.LimitReader(file, info.Size())
	packet := make([]byte, 4+request.blockSize)
	binary.BigEndian.PutUint16(packet, opData)
	for block := uint16(1); ; block++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(reader, packet[4:])
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			s.sendError(conn, peer, 0, "file read failed")
			return err
		}
		binary.BigEndian.PutUint16(packet[2:], block)
		if err := exchange(ctx, conn, peer, packet[:4+n], block, request.timeout); err != nil {
			return err
		}
		if n < request.blockSize {
			return nil
		}
		// uint16 wraps to block zero for files larger than 65535 blocks, as
		// implemented by PXE clients. Exact multiples end in an empty DATA block.
	}
}

// exchange retransmits on timeout only. Duplicate ACKs must not trigger DATA
// retransmissions (the RFC 1350 "Sorcerer's Apprentice" bug).
func exchange(ctx context.Context, conn *net.UDPConn, peer netip.AddrPort, packet []byte, block uint16, timeout time.Duration) error {
	response := make([]byte, maxRequestSize+1)
	for range maxAttempts {
		if err := ctx.Err(); err != nil {
			return err
		}
		deadline := time.Now().Add(timeout)
		if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
			deadline = end
		}
		if err := conn.SetDeadline(deadline); err != nil {
			return err
		}
		if _, err := conn.WriteToUDPAddrPort(packet, peer); err != nil {
			return err
		}
		for {
			n, sender, err := conn.ReadFromUDPAddrPort(response)
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					break
				}
				return err
			}
			if sender != peer {
				// A stray TID cannot acknowledge or terminate another client's transfer.
				if n >= 2 && binary.BigEndian.Uint16(response[:n]) != opError {
					if _, err := conn.WriteToUDPAddrPort(errorPacket(5, "unknown transfer ID"), sender); err != nil {
						return err
					}
				}
				continue
			}
			if n >= 4 && binary.BigEndian.Uint16(response[:n]) == opError {
				return errors.New("client terminated transfer")
			}
			if n == 4 && binary.BigEndian.Uint16(response[:n]) == opAck && binary.BigEndian.Uint16(response[2:n]) == block {
				return nil
			}
			// Stale, malformed and future ACKs do not extend the timeout.
		}
	}
	return errors.New("TFTP acknowledgement timed out")
}
