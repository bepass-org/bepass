package fragment

import (
	"bepass/config"
	"bepass/pkg/sni"
	"bytes"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Adapter represents an adapter for implementing fragmentation as net.Conn interface
type Adapter struct {
	conn         net.Conn
	readMutex    sync.Mutex
	writeMutex   sync.Mutex
	isFirstWrite bool
	// search for sni and if sni was found, initially split client hello packet to 3 packets
	// first chunk is contents of original tls hello packet before reaching sni
	// second packet is sni itself
	// and third package is contents of original tls hello packet after sni
	// we fragment each part separately BSL indicates each fragment's size(a range) for
	// original packet contents before reaching the sni
	// SL indicates each fragment's size(a range) for the sni itself
	// ASL indicates each fragment's size(a range) for remaining contents of original packet that comes after sni
	// and delay indicates how much delay system should take before sending next fragment as a separate packet
	BSL   [2]int
	SL    [2]int
	ASL   [2]int
	Delay [2]int
}

// New creates a new Adapter from a net.Conn connection.
func New(conn net.Conn) *Adapter {
	return &Adapter{
		conn:         conn,
		isFirstWrite: true,
		BSL:          config.Fragment.Advanced.Bsl,
		SL:           config.Fragment.Advanced.Sl,
		ASL:          config.Fragment.Advanced.Asl,
		Delay:        config.Fragment.Delay,
	}
}

// it will search for sni or host in package and if found then chunks Write writes data to the net.Conn connection.
func (a *Adapter) writeFragments(b []byte, index int) (int, error) {
	nw := 0
	position := 0
	lengthMin, lengthMax := 0, 0
	if index == 0 {
		lengthMin, lengthMax = a.BSL[0], a.BSL[1]
	} else if index == 1 { // if its sni
		lengthMin, lengthMax = a.SL[0], a.SL[1]
	} else { // if its after sni
		lengthMin, lengthMax = a.ASL[0], a.ASL[1]
	}
	for position < len(b) {
		var fragmentLength int
		if lengthMax-lengthMin > 0 {
			fragmentLength = rand.Intn(lengthMax-lengthMin) + lengthMin
		} else {
			fragmentLength = lengthMin
		}

		if fragmentLength > len(b)-position {
			fragmentLength = len(b) - position
		}

		var delay int
		if a.Delay[1]-a.Delay[0] > 0 {
			delay = rand.Intn(a.Delay[1]-a.Delay[0]) + a.Delay[0]
		} else {
			delay = a.Delay[0]
		}

		tnw, ew := a.conn.Write(b[position : position+fragmentLength])
		if ew != nil {
			return 0, ew
		}

		nw += tnw

		position += fragmentLength
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	return nw, nil
}

// it will search for sni or host in package and if found then chunks Write writes data to the net.Conn connection.
func (a *Adapter) fragmentAndWriteFirstPacket(b []byte) (int, error) {
	hello, err := sni.ReadClientHello(bytes.NewReader(b))
	if err != nil {
		return a.conn.Write(b)
	}
	helloPacketSni := []byte(hello.ServerName)
	chunks := make(map[int][]byte)

	/*
		splitting original hello packet to BeforeSNI, SNI, AfterSNI chunks
	*/
	// search for sni through original tls client hello
	index := bytes.Index(b, helloPacketSni)
	if index == -1 {
		return a.conn.Write(b)
	}
	// before helloPacketSni
	chunks[0] = make([]byte, index)
	copy(chunks[0], b[:index])

	// helloPacketSni
	// Create new rand source with seed
	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)

	var result strings.Builder

	// Use rng instead of rand
	for _, r := range string(helloPacketSni) {
		if rng.Intn(2) == 0 {
			result.WriteRune(unicode.ToUpper(r))
		} else {
			result.WriteRune(r)
		}
	}
	helloPacketSni = []byte(result.String())
	chunks[1] = make([]byte, len(helloPacketSni))
	copy(chunks[1], b[index:index+len(helloPacketSni)])

	// after helloPacketSni
	chunks[2] = make([]byte, len(b)-index-len(helloPacketSni))
	copy(chunks[2], b[index+len(helloPacketSni):])

	/*
		sending fragments
	*/
	// number of written packets
	nw := 0
	var ew error = nil

	for i := 0; i < 3; i++ {
		tnw, ew := a.writeFragments(chunks[i], i)
		nw += tnw
		if ew != nil {
			return 0, ew
		}
	}

	return nw, ew
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
		return a.fragmentAndWriteFirstPacket(b)
	} else {
		bytesWritten, err = a.conn.Write(b)
	}

	return bytesWritten, err
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
