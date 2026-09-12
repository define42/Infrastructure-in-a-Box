package nfsserver

import (
	"log/slog"

	nfslog "github.com/smallfz/libnfs-go/log"
)

// Upstream defaults to verbose, colored per-operation logging. Configure its
// process-global logger once during initialization, before any serving goroutines.
func init() {
	nfslog.SetLoggerDefault(nfslog.NewLogger("nfs", nfslog.ERROR, protocolLog{}))
}

type protocolLog struct{}

func (protocolLog) Write(message *nfslog.Message) {
	slog.Error("NFS protocol library", "message", message.Message)
}
