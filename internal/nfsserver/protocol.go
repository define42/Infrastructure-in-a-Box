package nfsserver

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/smallfz/libnfs-go/backend"
	nfsfs "github.com/smallfz/libnfs-go/fs"
	"github.com/smallfz/libnfs-go/nfs"
	v4 "github.com/smallfz/libnfs-go/nfs/implv4"
	"github.com/smallfz/libnfs-go/xdr"
)

const maxRecord = 2 << 20
const maxOperations = 64

func readRecord(r io.Reader) ([]byte, error) {
	var result []byte
	for fragments := 0; fragments < 64; fragments++ {
		var marker [4]byte
		if _, err := io.ReadFull(r, marker[:]); err != nil {
			return nil, err
		}
		value := binary.BigEndian.Uint32(marker[:])
		size := int(value & 0x7fffffff)
		if size > maxRecord-len(result) {
			return nil, errors.New("NFS record exceeds 2 MiB")
		}
		start := len(result)
		result = append(result, make([]byte, size)...)
		if _, err := io.ReadFull(r, result[start:]); err != nil {
			return nil, err
		}
		if value&0x80000000 != 0 {
			return result, nil
		}
	}
	return nil, errors.New("too many NFS record fragments")
}
func writeRecord(w io.Writer, data []byte) error {
	var marker [4]byte
	binary.BigEndian.PutUint32(marker[:], uint32(len(data))|0x80000000)
	_, err := io.Copy(w, io.MultiReader(bytes.NewReader(marker[:]), bytes.NewReader(data)))
	return err
}

// cursor validates lengths before libnfs-go's allocating XDR decoder sees data.
// It also separates compound operations so execution stops at the first failure.
type cursor struct {
	data   []byte
	offset int
	err    error
	size   *uint64
}

func (c *cursor) take(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || n > len(c.data)-c.offset {
		c.err = io.ErrUnexpectedEOF
		return nil
	}
	p := c.data[c.offset : c.offset+n]
	c.offset += n
	return p
}
func (c *cursor) word() uint32 {
	p := c.take(4)
	if p == nil {
		return 0
	}
	return binary.BigEndian.Uint32(p)
}
func (c *cursor) opaque(limit int) []byte {
	n := int(c.word())
	if n > limit {
		c.err = errors.New("oversized NFS XDR value")
		return nil
	}
	p := c.take(n)
	c.take((4 - n%4) % 4)
	return p
}
func (c *cursor) component() {
	name := string(c.opaque(255))
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
		c.err = errors.New("invalid NFS path component")
	}
}
func (c *cursor) bitmap() []uint32 {
	count := c.word()
	if count > 3 {
		c.err = errors.New("oversized NFS attribute bitmap")
		return nil
	}
	values := make([]uint32, count)
	for i := range values {
		values[i] = c.word()
	}
	return values
}
func (c *cursor) attrs() uint32 {
	mask := c.bitmap()
	data := c.opaque(4096)
	nested := cursor{data: data}
	status := nfs.NFS4_OK
	for word, bits := range mask {
		for bit := 0; bit < 32; bit++ {
			if bits&(1<<bit) == 0 {
				continue
			}
			// Only writable attributes understood by our adapter reach upstream's nested decoder.
			switch word*32 + bit {
			case 4:
				value := nested.take(8)
				if value != nil {
					size := binary.BigEndian.Uint64(value)
					c.size = &size
				}
			case 33:
				nested.take(4) // mode
			default:
				status = nfs.NFS4ERR_ATTRNOTSUPP
			}
		}
	}
	if status == nfs.NFS4_OK && (nested.err != nil || nested.offset != len(data)) {
		c.err = errors.New("invalid NFS attribute data")
	}
	return status
}

type operation struct {
	number uint32
	data   []byte
	status uint32
	access uint32
	size   *uint64
}

func (c *cursor) operation() operation {
	start := c.offset
	c.size = nil
	op := operation{number: c.word()}
	switch op.number {
	case nfs.OP4_PUTROOTFH, nfs.OP4_GETFH, nfs.OP4_SAVEFH, nfs.OP4_RESTOREFH, nfs.OP4_READLINK:
	case nfs.OP4_PUTFH:
		c.opaque(128)
	case nfs.OP4_LOOKUP, nfs.OP4_REMOVE, nfs.OP4_SECINFO, nfs.OP4_LINK:
		c.component()
	case nfs.OP4_RENAME:
		c.component()
		c.component()
	case nfs.OP4_GETATTR:
		c.bitmap()
	case nfs.OP4_ACCESS:
		c.take(4)
	case nfs.OP4_RENEW:
		c.take(8)
	case nfs.OP4_SETCLIENTID:
		c.take(8)
		c.opaque(1024)
		c.take(4)
		c.opaque(255)
		c.opaque(255)
		c.take(4)
	case nfs.OP4_SETCLIENTID_CONFIRM:
		c.take(16)
	case nfs.OP4_CLOSE:
		c.take(20)
	case nfs.OP4_COMMIT:
		c.take(12)
	case nfs.OP4_READ:
		c.take(24)
		if c.word() > maxIO {
			op.status = nfs.NFS4ERR_INVAL
		}
	case nfs.OP4_WRITE:
		c.take(28)
		c.opaque(maxIO)
	case nfs.OP4_READDIR:
		c.take(24)
		c.bitmap()
	case nfs.OP4_SETATTR:
		c.take(16)
		op.status = c.attrs()
	case nfs.OP4_CREATE:
		kind := c.word()
		switch kind {
		case nfs.NF4LNK:
			c.opaque(4096)
		case nfs.NF4BLK, nfs.NF4CHR:
			c.take(8)
		}
		c.component()
		op.status = c.attrs()
	case nfs.OP4_OPEN:
		c.take(4)
		op.access = c.word()
		deny := c.word()
		if op.access < 1 || op.access > 3 {
			op.status = nfs.NFS4ERR_INVAL
		}
		if deny != 0 {
			op.status = nfs.NFS4ERR_NOTSUPP
		}
		c.take(8)
		c.opaque(1024)
		how := c.word()
		if how == nfs.OPEN4_CREATE {
			switch c.word() {
			case nfs.UNCHECKED4, nfs.GUARDED4:
				if status := c.attrs(); status != 0 {
					op.status = status
				}
			case nfs.EXCLUSIVE4:
				c.take(8)
				op.status = nfs.NFS4ERR_NOTSUPP
			default:
				c.err = errors.New("invalid NFS create mode")
			}
		} else if how != nfs.OPEN4_NOCREATE {
			c.err = errors.New("invalid NFS open mode")
		}
		claim := c.word()
		if claim == nfs.CLAIM_NULL {
			c.component()
		} else {
			op.status = nfs.NFS4ERR_NOTSUPP
		}
	default:
		op.status = nfs.NFS4ERR_OP_ILLEGAL
	}
	op.size = c.size
	if op.number == nfs.OP4_OPEN && op.size != nil && *op.size != 0 {
		op.status = nfs.NFS4ERR_NOTSUPP
	}
	op.data = c.data[start:c.offset]
	return op
}

type session struct {
	filesystem *filesystem
	state      *backend.Stat
	files      map[*trackedFile]struct{}
}

func newSession(f *filesystem) *session {
	return &session{filesystem: f, state: new(backend.Stat), files: make(map[*trackedFile]struct{})}
}

func rpcReply(xid, status uint32, extra ...uint32) []byte {
	var b bytes.Buffer
	w := xdr.NewWriter(&b)
	for _, value := range append([]uint32{xid, nfs.RPC_REPLY, nfs.MSG_ACCEPTED, 0, 0, status}, extra...) {
		_, _ = w.WriteUint32(value)
	}
	return b.Bytes()
}

func (s *session) reply(data []byte) ([]byte, error) {
	c := cursor{data: data}
	xid, kind, rpcVersion, program, version, procedure := c.word(), c.word(), c.word(), c.word(), c.word(), c.word()
	flavor := c.word()
	c.opaque(400)
	c.word()
	c.opaque(400)
	if c.err != nil {
		return nil, c.err
	}
	if kind != nfs.RPC_CALL || rpcVersion != 2 {
		return nil, errors.New("invalid RPC call")
	}
	if program != 100003 {
		return rpcReply(xid, nfs.ACCEPT_PROG_UNAVAIL), nil
	}
	if version != 4 {
		return rpcReply(xid, nfs.ACCEPT_PROG_MISMATCH, 4, 4), nil
	}
	if procedure == nfs.PROC4_VOID {
		return rpcReply(xid, nfs.ACCEPT_SUCCESS), nil
	}
	if procedure != nfs.PROC4_COMPOUND {
		return rpcReply(xid, nfs.ACCEPT_PROC_UNAVAIL), nil
	}
	if flavor != nfs.AUTH_FLAVOR_NULL && flavor != nfs.AUTH_FLAVOR_UNIX {
		return nil, errors.New("unsupported NFS authentication flavor")
	}
	tag := c.opaque(1024)
	minor := c.word()
	count := c.word()
	if c.err != nil {
		return rpcReply(xid, nfs.ACCEPT_GRABAGE_ARGS), nil
	}
	status := nfs.NFS4_OK
	if minor != 0 {
		status = nfs.NFS4ERR_MINOR_VERS_MISMATCH
	}
	if count > maxOperations {
		return rpcReply(xid, nfs.ACCEPT_GRABAGE_ARGS), nil
	}
	// Filehandle registers are compound-local; opened files persist for this connection.
	s.state.SetCurrentHandle(nil)
	for {
		if _, ok := s.state.PopHandle(); !ok {
			break
		}
	}
	var results bytes.Buffer
	completed := uint32(0)
	for completed < count && status == nfs.NFS4_OK {
		op := c.operation()
		if c.err != nil {
			return rpcReply(xid, nfs.ACCEPT_GRABAGE_ARGS), nil
		}
		response, opStatus, err := s.execute(op)
		if err != nil {
			return nil, err
		}
		results.Write(response)
		status = opStatus
		completed++
	}
	var b bytes.Buffer
	b.Write(rpcReply(xid, nfs.ACCEPT_SUCCESS))
	w := xdr.NewWriter(&b)
	_, _ = w.WriteUint32(status)
	_, _ = w.WriteAny(tag)
	_, _ = w.WriteUint32(completed)
	b.Write(results.Bytes())
	return b.Bytes(), nil
}

func operationError(op, status uint32) []byte {
	var b bytes.Buffer
	w := xdr.NewWriter(&b)
	_, _ = w.WriteUint32(op)
	_, _ = w.WriteUint32(status)
	// SETATTR returns attrsset even on error.
	if op == nfs.OP4_SETATTR {
		_, _ = w.WriteUint32(0)
	}
	return b.Bytes()
}

func (s *session) execute(op operation) ([]byte, uint32, error) {
	if op.number == nfs.OP4_OPEN && len(s.files) >= 256 {
		op.status = nfs.NFS4ERR_RESOURCE
	}
	if op.status != 0 {
		return operationError(op.number, op.status), op.status, nil
	}
	if op.number == nfs.OP4_OPEN || op.number == nfs.OP4_CREATE || op.number == nfs.OP4_REMOVE || op.number == nfs.OP4_RENAME || op.number == nfs.OP4_SETATTR || op.number == nfs.OP4_WRITE || op.number == nfs.OP4_LINK {
		name, err := s.filesystem.ResolveHandle(s.state.CurrentHandle())
		if err == nil {
			e, _, _ := s.filesystem.resolve(name)
			if (name == "/" || (e != nil && e.readOnly)) && (op.number != nfs.OP4_OPEN || op.access&2 != 0) {
				return operationError(op.number, nfs.NFS4ERR_ROFS), nfs.NFS4ERR_ROFS, nil
			}
		}
	}
	var input, output bytes.Buffer
	w := xdr.NewWriter(&input)
	_, _ = w.WriteAny("")
	_, _ = w.WriteUint32(0)
	_, _ = w.WriteUint32(1)
	input.Write(op.data)
	ctx := &rpcContext{reader: xdr.NewReader(&input), writer: xdr.NewWriter(&output), state: s.state,
		operationFS: &operationFS{filesystem: s.filesystem, access: op.access, retain: op.number == nfs.OP4_OPEN, session: s, size: op.size, setattr: op.number == nfs.OP4_SETATTR}}
	defer ctx.closeFiles()
	header := &nfs.RPCMsgCall{MsgType: nfs.RPC_CALL, RPCVer: 2, Prog: 100003, Vers: 4, Proc: nfs.PROC4_COMPOUND, Cred: nfs.NewEmptyAuth(), Verf: nfs.NewEmptyAuth()}
	if _, err := v4.Compound(header, ctx); err != nil {
		return nil, 0, err
	}
	result := output.Bytes()
	// Empty-tag, one-operation compound: RPC header (24), status/tag/count (12).
	if len(result) < 44 {
		return nil, 0, errors.New("invalid response from NFS protocol library")
	}
	status := binary.BigEndian.Uint32(result[24:28])
	return bytes.Clone(result[36:]), status, nil
}

type operationFS struct {
	*filesystem
	access  uint32
	retain  bool
	files   []nfsfs.File
	session *session
	size    *uint64
	setattr bool
}

func (f *operationFS) Open(name string) (nfsfs.File, error) {
	flags := os.O_RDONLY
	if f.setattr {
		flags = os.O_RDWR
	}
	opened, err := f.filesystem.OpenFile(name, flags, 0)
	if err == nil {
		f.files = append(f.files, opened)
	}
	return opened, err
}
func (f *operationFS) OpenFile(name string, flags int, mode os.FileMode) (nfsfs.File, error) {
	if f.retain {
		// Upstream truncates all UNCHECKED creates, including opens of existing files.
		if f.size == nil {
			flags &^= os.O_TRUNC
		}
		flags &^= os.O_RDWR | os.O_WRONLY
		switch f.access {
		case 2:
			flags |= os.O_WRONLY
		case 3:
			flags |= os.O_RDWR
		}
	}
	opened, err := f.filesystem.OpenFile(name, flags, mode)
	if err == nil {
		if f.retain {
			tracked := &trackedFile{File: opened, session: f.session}
			f.session.files[tracked] = struct{}{}
			return tracked, nil
		}
		f.files = append(f.files, opened)
	}
	return opened, err
}
func (f *operationFS) closeFiles() {
	for _, file := range f.files {
		_ = file.Close()
	}
}

type rpcContext struct {
	*operationFS
	reader *xdr.Reader
	writer *xdr.Writer
	state  *backend.Stat
}

func (c *rpcContext) Reader() *xdr.Reader   { return c.reader }
func (c *rpcContext) Writer() *xdr.Writer   { return c.writer }
func (c *rpcContext) GetFS() nfsfs.FS       { return c.operationFS }
func (c *rpcContext) Stat() nfs.StatService { return c.state }
func (*rpcContext) Authenticate(*nfs.Auth, *nfs.Auth) (*nfs.Auth, error) {
	return nfs.NewEmptyAuth(), nil
}

// trackedFile bounds descriptors per session and closes them even if upstream
// opens a file but fails before registering its state ID.
type trackedFile struct {
	nfsfs.File
	session *session
	closed  bool
}

func (f *trackedFile) Close() error {
	if f.closed {
		return nil
	}
	f.closed = true
	delete(f.session.files, f)
	return f.File.Close()
}
func (s *session) close() {
	s.state.CleanUp()
	for file := range s.files {
		_ = file.Close()
	}
}
