package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func bootTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := testServer(t, testPKI(t))
	root := bootTestDirectory(t)
	s.config.BootDirectory = root
	return s, root
}

func bootTestDirectory(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "boot")
	if err := os.MkdirAll(filepath.Join(root, "pxelinux.cfg"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"bootx64.efi": "0123456789abcdef", "pxelinux.cfg/default": "DEFAULT linux\n"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestBootFilesAndDirectories(t *testing.T) {
	t.Parallel()
	s, root := bootTestServer(t)
	for _, tc := range []struct {
		path, method, rangeHeader string
		code                      int
		want                      string
	}{
		{"/boot/bootx64.efi", "GET", "", 200, "0123456789abcdef"},
		{"/boot/bootx64.efi", "HEAD", "", 200, ""},
		{"/boot/bootx64.efi", "GET", "bytes=3-7", 206, "34567"},
		{"/boot/bootx64.efi", "GET", "bytes=-4", 206, "cdef"},
		{"/boot/pxelinux.cfg/default", "GET", "", 200, "DEFAULT linux\n"},
	} {
		t.Run(tc.method+tc.path+tc.rangeHeader, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.rangeHeader != "" {
				r.Header.Set("Range", tc.rangeHeader)
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != tc.code || w.Body.String() != tc.want {
				t.Fatalf("response = %d %q", w.Code, w.Body.String())
			}
			if w.Header().Get("Accept-Ranges") != "bytes" || w.Header().Get("Last-Modified") == "" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("missing download/security headers")
			}
			if tc.method == "HEAD" && w.Header().Get("Content-Length") != "16" {
				t.Fatal("HEAD did not report file size")
			}
			if tc.rangeHeader == "bytes=3-7" && w.Header().Get("Content-Range") != "bytes 3-7/16" {
				t.Fatal("incorrect Content-Range")
			}
		})
	}
	for _, path := range []string{"/boot/", "/boot/pxelinux.cfg/"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), "href=") {
			t.Fatalf("directory not exposed: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/boot?version=1", nil))
	if w.Code != 301 || w.Header().Get("Location") != "/boot/?version=1" {
		t.Fatal("missing directory redirect")
	}
	// Updates to the shared root are immediately visible without restarting HTTPS.
	if err := os.WriteFile(filepath.Join(root, "bootx64.efi"), []byte("updated"), 0644); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/boot/bootx64.efi", nil))
	if w.Code != 200 || w.Body.String() != "updated" {
		t.Fatal("file update was not visible")
	}
}

func TestBootFilesConfinePathsAndRejectWrites(t *testing.T) {
	t.Parallel()
	s, root := bootTestServer(t)
	secret := filepath.Join(filepath.Dir(root), "secret")
	if err := os.WriteFile(secret, []byte("PRIVATE DATA"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(root), filepath.Join(root, "outside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("bootx64.efi", filepath.Join(root, "inside")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/boot/../secret", "/boot/%2e%2e/secret", "/boot/pxelinux.cfg/../../secret", "/boot/%2e%2e%2fsecret",
		"/boot/..%5csecret", "/boot/escape", "/boot/outside/secret", "/boot/fifo", "/boot/%00secret", "/boot/missing", "/boot-other/bootx64.efi",
	} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
			if w.Code != 403 && w.Code != 404 {
				t.Fatalf("unsafe request: %d %s", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "PRIVATE DATA") || strings.Contains(w.Body.String(), secret) {
				t.Fatal("private data or filesystem path leaked")
			}
		})
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest(method, "/boot/bootx64.efi", strings.NewReader("changed")))
		if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
			t.Fatalf("write method accepted: %d", w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/boot/inside", nil))
	if w.Code != 200 || w.Body.String() != "0123456789abcdef" {
		t.Fatal("confined file link failed or writes modified data")
	}
}

func TestBootRootCanAppearAfterGatewayStartup(t *testing.T) {
	t.Parallel()
	s := testServer(t, testPKI(t))
	s.config.BootDirectory = filepath.Join(t.TempDir(), "later")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/boot/bootx64.efi", nil))
	if w.Code != 404 {
		t.Fatalf("missing root: %d", w.Code)
	}
	if err := os.Mkdir(s.config.BootDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.config.BootDirectory, "bootx64.efi"), []byte("boot"), 0644); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/boot/bootx64.efi", nil))
	if w.Code != 200 || w.Body.String() != "boot" {
		t.Fatal("new TFTP root is unavailable over HTTPS")
	}
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadline time.Time
}

func (r *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.deadline = deadline
	return nil
}

func TestBootDownloadsExtendWriteDeadline(t *testing.T) {
	t.Parallel()
	s, _ := bootTestServer(t)
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/boot/bootx64.efi", nil))
	if w.Code != 200 || time.Until(w.deadline) < 9*time.Minute || time.Until(w.deadline) > 10*time.Minute {
		t.Fatalf("missing bounded boot deadline: %v", w.deadline)
	}
}
