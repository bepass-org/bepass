// Package wsconnadapter provides an adapter for representing WebSocket connections as net.Conn objects.
// It allows you to use WebSocket connections as if they were standard network connections.
package wsconnadapter

import (
	"errors"
	"github.com/gorilla/websocket"
	"io"
	"net"
	"sync"
	"time"
)

// Adapter represents an adapter for representing WebSocket connection as a net.Conn.
// Some caveats apply: https://github.com/gorilla/websocket/issues/441
type Adapter struct {
	conn       *websocket.Conn
	readMutex  sync.Mutex
	writeMutex sync.Mutex
	reader     io.Reader
}

// New creates a new Adapter from a WebSocket connection.
func New(conn *websocket.Conn) *Adapter {
	return &Adapter{
		conn: conn,
	}
}

// Read reads data from the WebSocket connection.
func (a *Adapter) Read(b []byte) (int, error) {
	// Read() can be called concurrently, and we mutate some internal state here
	a.readMutex.Lock()
	defer a.readMutex.Unlock()

	if a.reader == nil {
		messageType, reader, err := a.conn.NextReader()
		if err != nil {
			return 0, err
		}

		if messageType != websocket.BinaryMessage {
			return 0, errors.New("unexpected websocket message type")
		}

		a.reader = reader
	}

	bytesRead, err := a.reader.Read(b)
	if err != nil {
		a.reader = nil

		// EOF for the current Websocket frame, more will probably come so..
		if err == io.EOF {
			// .. we must hide this from the caller since our semantics are a
			// stream of bytes across many frames
			err = nil
		}
	}
	return bytesRead, err
}

// Write writes data to the WebSocket connection.
func (a *Adapter) Write(b []byte) (int, error) {
	a.writeMutex.Lock()
	defer a.writeMutex.Unlock()

	nextWriter, err := a.conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}

	bytesWritten, err := nextWriter.Write(b)
	nextWriter.Close()

	return bytesWritten, err
}

// Close closes the WebSocket connection.
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
