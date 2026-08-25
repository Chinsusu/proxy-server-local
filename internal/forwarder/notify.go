package forwarder

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
)

// Notifier makes readiness testable without a running systemd manager.
type Notifier interface {
	Ready(status string) error
	Stopping(status string) error
}

type systemdNotifier struct {
	socket string
}

// NewSystemdNotifier uses NOTIFY_SOCKET when systemd supplied it. Outside
// systemd it is a no-op so development runs remain possible.
func NewSystemdNotifier() Notifier {
	return systemdNotifier{socket: os.Getenv("NOTIFY_SOCKET")}
}

func (n systemdNotifier) Ready(status string) error {
	return n.send("READY=1\nSTATUS=" + cleanStatus(status))
}

func (n systemdNotifier) Stopping(status string) error {
	return n.send("STOPPING=1\nSTATUS=" + cleanStatus(status))
}

func (n systemdNotifier) send(message string) error {
	if n.socket == "" {
		return nil
	}
	path := n.socket
	if strings.HasPrefix(path, "@") {
		path = "\x00" + path[1:]
	}
	if !strings.HasPrefix(path, "\x00") && !strings.HasPrefix(path, "/") {
		return errors.New("invalid systemd notify socket")
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	written, err := conn.Write([]byte(message))
	if err != nil {
		return err
	}
	if written != len(message) {
		return io.ErrShortWrite
	}
	return nil
}

func cleanStatus(status string) string {
	return strings.NewReplacer("\n", " ", "\r", " ").Replace(status)
}
