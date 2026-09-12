package nfsserver

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
	nfsfs "github.com/smallfz/libnfs-go/fs"
)

const maxHandles = 65536
const maxIO = 1 << 20

type export struct {
	root     *os.Root
	readOnly bool
}

type handleEntry struct {
	name   string
	info   os.FileInfo
	handle [16]byte
}

// filesystem exposes only configured roots. os.Root enforces containment even
// when a local process concurrently renames directories or replaces symlinks.
type filesystem struct {
	exports  map[string]*export
	mu       sync.Mutex
	handles  map[[16]byte]*handleEntry
	paths    map[string]*handleEntry
	rootInfo *fileInfo
}

var _ nfsfs.FS = (*filesystem)(nil)

func openFilesystem(shares []config.NFSShare) (*filesystem, error) {
	f := &filesystem{exports: make(map[string]*export), handles: make(map[[16]byte]*handleEntry), paths: make(map[string]*handleEntry)}
	f.rootInfo = &fileInfo{name: "/", readOnly: true, modified: time.Now()}
	f.rootInfo.handle = [16]byte{1}
	// Resolve configured symlinks once, also rejecting aliases that defeat read-only separation.
	resolved := make([]config.NFSShare, 0, len(shares))
	for _, share := range shares {
		real, err := filepath.EvalSymlinks(share.Path)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		share.Path = real
		resolved = append(resolved, share)
	}
	if err := config.ValidateNFSShares(resolved); err != nil {
		return nil, err
	}
	for _, share := range resolved {
		root, err := os.OpenRoot(share.Path)
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		f.exports[share.Name] = &export{root: root, readOnly: share.ReadOnly}
	}
	return f, nil
}

func (f *filesystem) Close() error {
	var err error
	for _, e := range f.exports {
		err = errors.Join(err, e.root.Close())
	}
	return err
}

func (*filesystem) SetCreds(nfsfs.Creds) {} // All clients use the service OS identity; no UID impersonation.
func (*filesystem) Attributes() *nfsfs.Attributes {
	return &nfsfs.Attributes{ChownRestricted: true, MaxName: 255, MaxRead: maxIO, MaxWrite: maxIO, NoTrunc: true}
}

func (f *filesystem) resolve(name string) (*export, string, error) {
	if !strings.HasPrefix(name, "/") || path.Clean(name) != name || strings.ContainsRune(name, 0) {
		return nil, "", os.ErrPermission
	}
	parts := strings.SplitN(strings.TrimPrefix(name, "/"), "/", 2)
	e := f.exports[parts[0]]
	if e == nil {
		return nil, "", os.ErrNotExist
	}
	relative := "."
	if len(parts) == 2 {
		relative = filepath.FromSlash(parts[1])
	}
	return e, relative, nil
}

func (f *filesystem) wrap(name string, info os.FileInfo, readOnly bool) (*fileInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entry := f.paths[name]
	if entry == nil || !os.SameFile(entry.info, info) {
		if len(f.handles) >= maxHandles {
			return nil, syscall.ENFILE
		}
		entry = &handleEntry{name: name, info: info}
		if _, err := rand.Read(entry.handle[:]); err != nil {
			return nil, err
		}
		f.paths[name] = entry
		f.handles[entry.handle] = entry
	}
	return &fileInfo{FileInfo: info, name: path.Base(name), handle: entry.handle, readOnly: readOnly}, nil
}

func (f *filesystem) Stat(name string) (nfsfs.FileInfo, error) {
	if name == "/" {
		return f.rootInfo, nil
	}
	e, relative, err := f.resolve(name)
	if err != nil {
		return nil, err
	}
	info, err := e.root.Stat(relative)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return nil, os.ErrPermission
	}
	return f.wrap(name, info, e.readOnly)
}

func (f *filesystem) Open(name string) (nfsfs.File, error) { return f.OpenFile(name, os.O_RDONLY, 0) }
func (f *filesystem) OpenFile(name string, flag int, mode os.FileMode) (nfsfs.File, error) {
	if name == "/" {
		if flag != os.O_RDONLY {
			return nil, os.ErrPermission
		}
		var entries []nfsfs.FileInfo
		for share := range f.exports {
			info, err := f.Stat("/" + share)
			if err != nil {
				return nil, err
			}
			entries = append(entries, info)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		return &file{filesystem: f, name: name, readOnly: true, entries: entries}, nil
	}
	e, relative, err := f.resolve(name)
	if err != nil {
		return nil, err
	}
	if e.readOnly {
		if flag&(os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0 {
			return nil, syscall.EROFS
		}
		// libnfs-go opens existing files O_RDWR even for NFS OPEN(READ).
		// Open a genuinely read-only descriptor and reject all later mutations.
		flag = os.O_RDONLY
	}
	// O_NONBLOCK prevents a FIFO swapped in between Stat and Open from hanging.
	// Verify the opened object before exposing it to the protocol implementation.
	opened, err := e.root.OpenFile(relative, flag|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, mode.Perm())
	if err != nil {
		return nil, err
	}
	info, err := opened.Stat()
	if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
		_ = opened.Close()
		if err != nil {
			return nil, err
		}
		return nil, os.ErrPermission
	}
	return &file{File: opened, filesystem: f, name: name, readOnly: e.readOnly}, nil
}

func (f *filesystem) writable(name string) (*export, string, error) {
	e, relative, err := f.resolve(name)
	if err != nil {
		return nil, "", err
	}
	if e.readOnly {
		return nil, "", syscall.EROFS
	}
	if relative == "." {
		return nil, "", os.ErrPermission
	}
	return e, relative, nil
}
func (f *filesystem) Chmod(name string, mode os.FileMode) error {
	e, relative, err := f.writable(name)
	if err != nil {
		return err
	}
	return e.root.Chmod(relative, mode.Perm())
}
func (*filesystem) Chown(string, int, int) error { return os.ErrPermission }

// Links are deliberately unsupported: hard links could bypass export policies.
func (*filesystem) Symlink(string, string) error    { return os.ErrPermission }
func (*filesystem) Link(string, string) error       { return os.ErrPermission }
func (*filesystem) Readlink(string) (string, error) { return "", os.ErrPermission }
func (f *filesystem) MkdirAll(name string, mode os.FileMode) error {
	e, relative, err := f.writable(name)
	if err != nil {
		return err
	}
	return e.root.MkdirAll(relative, mode.Perm())
}
func (f *filesystem) Remove(name string) error {
	e, relative, err := f.writable(name)
	if err != nil {
		return err
	}
	if err := e.root.Remove(relative); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.paths, name) // Old opaque handles become stale, never reused for a new file.
	return nil
}
func (f *filesystem) Rename(oldName, newName string) error {
	oldExport, oldRelative, err := f.writable(oldName)
	if err != nil {
		return err
	}
	newExport, newRelative, err := f.writable(newName)
	if err != nil {
		return err
	}
	if oldExport != newExport {
		return syscall.EXDEV
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := oldExport.root.Rename(oldRelative, newRelative); err != nil {
		return err
	}
	delete(f.paths, newName)
	updates := make(map[string]*handleEntry)
	for name, entry := range f.paths {
		if name == oldName || strings.HasPrefix(name, oldName+"/") {
			delete(f.paths, name)
			entry.name = newName + strings.TrimPrefix(name, oldName)
			updates[entry.name] = entry
		}
	}
	for name, entry := range updates {
		f.paths[name] = entry
	}
	return nil
}
func (*filesystem) GetFileId(info nfsfs.FileInfo) uint64 {
	if fi, ok := info.(*fileInfo); ok {
		return binary.BigEndian.Uint64(fi.handle[:8])
	}
	return 0
}
func (f *filesystem) GetRootHandle() []byte { return append([]byte(nil), f.rootInfo.handle[:]...) }
func (*filesystem) GetHandle(info nfsfs.FileInfo) ([]byte, error) {
	fi, ok := info.(*fileInfo)
	if !ok {
		return nil, os.ErrInvalid
	}
	return append([]byte(nil), fi.handle[:]...), nil
}
func (f *filesystem) ResolveHandle(handle []byte) (string, error) {
	if len(handle) != 16 {
		return "", os.ErrNotExist
	}
	key := [16]byte(handle)
	if key == f.rootInfo.handle {
		return "/", nil
	}
	f.mu.Lock()
	entry := f.handles[key]
	if entry == nil {
		f.mu.Unlock()
		return "", os.ErrNotExist
	}
	name, info := entry.name, entry.info
	current := f.paths[name] == entry
	f.mu.Unlock()
	if !current {
		return "", os.ErrNotExist
	}
	e, relative, err := f.resolve(name)
	if err != nil {
		return "", err
	}
	actual, err := e.root.Stat(relative)
	if err != nil {
		return "", err
	}
	if !os.SameFile(info, actual) {
		return "", os.ErrNotExist
	}
	return name, nil
}

type fileInfo struct {
	os.FileInfo
	name     string
	handle   [16]byte
	readOnly bool
	modified time.Time
}

func (f *fileInfo) Name() string { return f.name }
func (f *fileInfo) Size() int64 {
	if f.FileInfo == nil {
		return 0
	}
	return f.FileInfo.Size()
}
func (f *fileInfo) Mode() os.FileMode {
	mode := os.ModeDir | 0555
	if f.FileInfo != nil {
		mode = f.FileInfo.Mode()
	}
	if f.readOnly {
		mode &^= 0222
	}
	return mode
}
func (f *fileInfo) ModTime() time.Time {
	if f.FileInfo == nil {
		return f.modified
	}
	return f.FileInfo.ModTime()
}
func (f *fileInfo) IsDir() bool { return f.Mode().IsDir() }
func (f *fileInfo) Sys() any {
	if f.FileInfo == nil {
		return nil
	}
	return f.FileInfo.Sys()
}
func (f *fileInfo) ATime() time.Time { return f.ModTime() }
func (f *fileInfo) CTime() time.Time { return f.ModTime() }
func (*fileInfo) NumLinks() int      { return 1 }

type file struct {
	*os.File
	filesystem *filesystem
	name       string
	readOnly   bool
	entries    []nfsfs.FileInfo
	offset     int
}

var _ nfsfs.File = (*file)(nil)

func (f *file) Name() string { return f.name }
func (f *file) Close() error {
	if f.File == nil {
		return nil
	}
	return f.File.Close()
}
func (f *file) Stat() (nfsfs.FileInfo, error) {
	if f.File == nil {
		return f.filesystem.rootInfo, nil
	}
	info, err := f.File.Stat()
	if err != nil {
		return nil, err
	}
	return f.filesystem.wrap(f.name, info, f.readOnly)
}
func (f *file) Read(p []byte) (int, error) {
	if f.File == nil {
		return 0, syscall.EISDIR
	}
	return f.File.Read(p)
}
func (f *file) Write(p []byte) (int, error) {
	if f.readOnly {
		return 0, syscall.EROFS
	}
	if len(p) > maxIO {
		return 0, os.ErrInvalid
	}
	return f.File.Write(p)
}
func (f *file) Seek(offset int64, whence int) (int64, error) {
	if f.File == nil {
		if offset == 0 && whence == io.SeekStart {
			f.offset = 0
			return 0, nil
		}
		return 0, os.ErrInvalid
	}
	return f.File.Seek(offset, whence)
}
func (f *file) Truncate() error {
	if f.readOnly {
		return syscall.EROFS
	}
	offset, err := f.File.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	return f.File.Truncate(offset)
}
func (f *file) Sync() error {
	if f.File == nil || f.readOnly {
		return nil
	}
	return f.File.Sync()
}
func (f *file) Readdir(n int) ([]nfsfs.FileInfo, error) {
	if f.File == nil {
		if f.offset == len(f.entries) && n > 0 {
			return nil, io.EOF
		}
		end := len(f.entries)
		if n > 0 && f.offset+n < end {
			end = f.offset + n
		}
		result := f.entries[f.offset:end]
		f.offset = end
		return result, nil
	}
	all := n <= 0
	if all {
		n = maxHandles + 1
	}
	infos, err := f.File.Readdir(n)
	if all && errors.Is(err, io.EOF) {
		err = nil
	}
	if len(infos) > maxHandles {
		return nil, syscall.ENFILE
	}
	entries := make([]nfsfs.FileInfo, 0, len(infos))
	for _, info := range infos {
		if !info.IsDir() && !info.Mode().IsRegular() {
			continue
		}
		wrapped, wrapErr := f.filesystem.wrap(path.Join(f.name, info.Name()), info, f.readOnly)
		if wrapErr != nil {
			return nil, wrapErr
		}
		entries = append(entries, wrapped)
	}
	return entries, err
}
