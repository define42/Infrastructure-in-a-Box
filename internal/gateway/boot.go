package gateway

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"
)

func (s *Server) serveBoot(w http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/boot" {
		target := "/boot/"
		if request.URL.RawQuery != "" {
			target += "?" + request.URL.RawQuery
		}
		http.Redirect(w, request, target, http.StatusMovedPermanently)
		return
	}
	name := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/boot/"), "/")
	if name != "" && (!fs.ValidPath(name) || strings.ContainsAny(name, "\\\x00")) {
		s.write(w, request, http.StatusNotFound, "text/plain; charset=utf-8", []byte("not found\n"))
		return
	}
	// Open per request so the handler needs no persistent file descriptor and
	// works when TFTP creates the directory after the gateway is constructed.
	root, err := os.OpenRoot(s.config.BootDirectory)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.logger.Debug("open boot directory", "error", err)
		}
		s.write(w, request, http.StatusNotFound, "text/plain; charset=utf-8", []byte("not found\n"))
		return
	}
	defer func() { _ = root.Close() }()
	// Boot images can take longer than the gateway's normal 15-second response
	// limit. Keep downloads bounded, with the same limit as a TFTP transfer.
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Minute)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		s.logger.Debug("set boot download deadline", "error", err)
	}
	http.StripPrefix("/boot/", http.FileServerFS(bootFiles{root: root})).ServeHTTP(w, request)
}

// bootFiles preserves os.Root confinement while rejecting special files before
// the HTTP file server reads them. Nonblocking open prevents FIFO reads hanging.
type bootFiles struct{ root *os.Root }

func (f bootFiles) Open(name string) (fs.File, error) {
	file, err := f.root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fs.ErrNotExist
		}
		return nil, fs.ErrPermission
	}
	info, err := file.Stat()
	if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
		_ = file.Close()
		return nil, fs.ErrPermission
	}
	return file, nil
}
