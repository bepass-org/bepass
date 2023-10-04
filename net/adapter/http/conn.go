package http

import (
	"bytes"
	"github.com/bepass-org/bepass/logger"
	"github.com/bepass-org/bepass/sni"
	"net"
	"sync"
	"time"
)

// Adapter represents an adapter for implementing fragmentation as net.Conn interface
type Adapter struct {
	conn         net.Conn
	readMutex    sync.Mutex
	writeMutex   sync.Mutex
	isFirstWrite bool
}

// New creates a new Adapter from a net.Conn connection.
func New(conn net.Conn) *Adapter {
	return &Adapter{
		conn:         conn,
		isFirstWrite: true,
	}
}

// Read reads data from the net.Conn connection.
func (a *Adapter) Read(b []byte) (int, error) {
	// Read() can be called concurrently, and we mutate some internal state here
	a.readMutex.Lock()
	defer a.readMutex.Unlock()

	bytesRead, err := a.conn.Read(b)
	if err != nil {
		return 0, err
	}
	return bytesRead, err
}

// Write writes data to the net.Conn connection.
func (a *Adapter) Write(b []byte) (int, error) {
	a.writeMutex.Lock()
	defer a.writeMutex.Unlock()

	var (
		bytesWritten int
		err          error
	)

	if a.isFirstWrite {
		a.isFirstWrite = false
		host, httpPacketData, err := sni.ParseHTTPHost(bytes.NewReader(b))
		if err != nil {
			return a.conn.Write(b)
		}
		logger.Info("found http packet host: %s", host)
		_, err = a.conn.Write(httpPacketData)
		if err != nil {
			return 0, err
		}
		return len(b), nil
	} else {
		bytesWritten, err = a.conn.Write(b)
	}

	return bytesWritten, err
}

// Close closes the net.Conn connection.
func (a *Adapter) Close() error {
	return a.conn.Close()
}

// LocalAddr returns the local network address.
func (a *Adapter) LocalAddr() net.Addr {
	return a.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (a *Adapter) RemoteAddr() net.Addr {
	return a.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines for the connection.
func (a *Adapter) SetDeadline(t time.Time) error {
	if err := a.SetReadDeadline(t); err != nil {
		return err
	}

	return a.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline for the connection.
func (a *Adapter) SetReadDeadline(t time.Time) error {
	return a.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline for the connection.
func (a *Adapter) SetWriteDeadline(t time.Time) error {
	return a.conn.SetWriteDeadline(t)
}
