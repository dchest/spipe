// Package spipe implements Colin Percival's spiped protocol
// (http://www.tarsnap.com/spiped.html) for creating symmetrically
// encrypted and authenticated connections.
//
// It requires a pre-shared symmetric key between client and server.
//
//
// The Dial function connects to a server and performs handshake:
//
// 	conn, err := spipe.Dial(sharedKey, "tcp", "127.0.0.1:8080")
// 	if err != nil {
// 		// handle error
// 	}
// 	fmt.Fprintf(conn, "Hello\n")
//
// The Listen function creates servers:
//
// 	ln, err := spipe.Listen(sharedKey, "tcp", ":8080")
// 	if err != nil {
// 		// handle error
// 	}
// 	for {
// 		conn, err := ln.Accept()
// 		if err != nil {
// 			// handle error
// 			continue
// 		}
// 		go handleConnection(conn)
// 	}
//
package spipe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"net"
	"sync"
	"time"

	"code.google.com/p/go.crypto/pbkdf2"
	"github.com/dchest/dhgroup14"
)

const (
	messageSize = 1024                      // maximum size of message inside packet
	payloadSize = messageSize + 4           // payload = padded message || message length
	packetSize  = payloadSize + sha256.Size // packet  = payload || MAC
)

type encryptor struct {
	sync.Mutex
	blockCipher cipher.Block
	mac         hash.Hash
	packetNum   uint64 // packet counter

	buf    [packetSize]byte // packet buffer
	buflen int              // number of unwritten bytes in buffer

	out io.Writer // underlying writer
}

func newEncryptor(w io.Writer, cipherKey, hmacKey []byte) *encryptor {
	blockCipher, err := aes.NewCipher(cipherKey)
	if err != nil {
		panic("gospiped: " + err.Error())
	}
	return &encryptor{
		blockCipher: blockCipher,
		mac:         hmac.New(sha256.New, hmacKey),
		out:         w,
	}
}

func (w *encryptor) flushBuffer() error {
	n, err := w.out.Write(w.buf[len(w.buf)-w.buflen:])
	w.buflen -= n
	if err != nil {
		// Wrote partial packet.
		return err
	}
	if w.buflen != 0 {
		// Writers must always return error on partial write,
		// but just in case our underlying writer is broken,
		// return our own error.
		return errors.New("gospiped: wrote partial packet")
	}
	// Wrote full packet.
	// Increment packet counter.
	w.packetNum++
	// Clear buffer.
	for i := range w.buf {
		w.buf[i] = 0
	}
	return nil
}

func (w *encryptor) Flush() error {
	return w.flushBuffer()
}

func (w *encryptor) sealPacket() {
	// Create iv from packet number.
	var iv [16]byte
	binary.BigEndian.PutUint64(iv[:8], w.packetNum)

	// Encrypt.
	c := cipher.NewCTR(w.blockCipher, iv[:])
	c.XORKeyStream(w.buf[:payloadSize], w.buf[:payloadSize])

	// Authenticate (payload || packet number).
	w.mac.Reset()
	w.mac.Write(w.buf[:payloadSize])
	w.mac.Write(iv[:8])
	w.mac.Sum(w.buf[payloadSize:payloadSize])

	// Set buffer length to packet size.
	w.buflen = packetSize
}

func (w *encryptor) Write(p []byte) (nn int, err error) {
	// Lock writer for the whole write.
	w.Lock()
	defer w.Unlock()

	// Write leftovers.
	if w.buflen > 0 {
		if err := w.flushBuffer(); err != nil {
			return 0, err
		}
	}

	// Split p into messages, turn them into encrypted and authenticated
	// packets, and write packets to w.out.
	for len(p) > 0 {
		// Copy message into buffer.
		msgLen := copy(w.buf[:messageSize], p)

		// Put message length to the last 4 bytes of payload.
		binary.BigEndian.PutUint32(w.buf[messageSize:], uint32(msgLen))

		// Encrypt and authenticate.
		w.sealPacket()

		// Increment written input bytes counter.
		nn += msgLen
		p = p[msgLen:]

		// Write packet.
		if err := w.flushBuffer(); err != nil {
			return nn, err
		}
	}
	return
}

type decryptor struct {
	sync.Mutex
	blockCipher cipher.Block
	mac         hash.Hash
	packetNum   uint64 // packet counter

	buf    [packetSize]byte // packet buffer
	buflen int              // number of bytes in buffer
	msg    []byte           // slice of unread message bytes in buffer

	in io.Reader // underlying reader
}

func newDecryptor(r io.Reader, cipherKey, hmacKey []byte) *decryptor {
	blockCipher, err := aes.NewCipher(cipherKey)
	if err != nil {
		panic("gospiped: " + err.Error())
	}
	return &decryptor{
		blockCipher: blockCipher,
		mac:         hmac.New(sha256.New, hmacKey),
		in:          r,
	}
}

func (r *decryptor) openPacket() error {
	// Create iv from packet number.
	var iv [16]byte
	binary.BigEndian.PutUint64(iv[:8], r.packetNum)

	// Authenticate.
	var sum [32]byte
	r.mac.Reset()
	r.mac.Write(r.buf[:payloadSize])
	r.mac.Write(iv[:8])
	if subtle.ConstantTimeCompare(r.mac.Sum(sum[:0]), r.buf[payloadSize:]) != 1 {
		return errors.New("gospiped: failed to authenticate packet")
	}

	// Increment packet counter.
	// Note: We increment counter only after successfully authenticating packets.
	r.packetNum++

	// Decrypt.
	c := cipher.NewCTR(r.blockCipher, iv[:])
	c.XORKeyStream(r.buf[:payloadSize], r.buf[:payloadSize])

	// Read message length.
	msgLen := binary.BigEndian.Uint32(r.buf[messageSize:])
	if msgLen > messageSize {
		return errors.New("gospiped: message length is too large")
	}

	r.msg = r.buf[:msgLen]
	return nil
}

func (r *decryptor) Read(p []byte) (nn int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Lock reader for the whole read.
	r.Lock()
	defer r.Unlock()

	// Copy leftovers.
	if len(r.msg) > 0 {
		n := copy(p, r.msg)
		p = p[n:]
		r.msg = r.msg[n:]
		nn += n
	}

	if len(p) > 0 {
		// Read packet.
		n, err := r.in.Read(r.buf[r.buflen:])
		r.buflen += n
		if r.buflen == packetSize {
			// Got full packet, decrypt.
			r.buflen = 0
			if err := r.openPacket(); err != nil {
				return nn, err
			}
			// Copy message (or part of it).
			n := copy(p, r.msg)
			p = p[n:]
			r.msg = r.msg[n:]
			nn += n
		}
		if err != nil {
			return nn, err
		}
	}
	return
}

type connection struct {
	w *encryptor
	r *decryptor

	isClient  bool
	secretKey []byte

	handshakeMutex     sync.Mutex
	handshakePerformed bool

	conn net.Conn // underlying connection
}

func (c *connection) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *connection) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *connection) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *connection) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *connection) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *connection) sendBytes(p []byte) error {
	n, err := c.conn.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return errors.New("gospiped: partial write")
	}
	return nil
}

func (c *connection) receiveBytes(p []byte) error {
	if _, err := io.ReadFull(c.conn, p); err != nil {
		return err
	}
	return nil
}

func (c *connection) handshake() error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if c.handshakePerformed {
		return nil
	}

	var nonces [32 + 32 + dhgroup14.SharedKeySize]byte
	if _, err := io.ReadFull(rand.Reader, nonces[:64]); err != nil {
		return err
	}
	nonceC := nonces[0:32]
	nonceS := nonces[32:64]

	// Send and receive random nonces.
	if c.isClient {
		if err := c.sendBytes(nonceC); err != nil {
			return err
		}
		if err := c.receiveBytes(nonceS); err != nil {
			return err
		}
	} else {
		if err := c.receiveBytes(nonceC); err != nil {
			return err
		}
		if err := c.sendBytes(nonceS); err != nil {
			return err
		}
	}

	// Generate dhmac_C and dhmac_S.
	dk1 := pbkdf2.Key(c.secretKey, nonces[:64], 1, 64, sha256.New)
	dhmacC := dk1[0:32]
	dhmacS := dk1[32:64]

	var myDHMac, theirDHMac []byte
	if c.isClient {
		myDHMac = dhmacC
		theirDHMac = dhmacS
	} else {
		myDHMac = dhmacS
		theirDHMac = dhmacC
	}

	// Generate DH key pair.
	myPublicKey, myPrivateKey, err := dhgroup14.GenerateKeyPair(rand.Reader)
	if err != nil {
		return err
	}

	// Prepare my public key for sending.
	var myAuthPublicKey [256 + 32]byte
	copy(myAuthPublicKey[:], myPublicKey)

	// Authenticate my public key.
	h := hmac.New(sha256.New, myDHMac)
	h.Write(myAuthPublicKey[0:256])
	h.Sum(myAuthPublicKey[256:256])

	var theirAuthPublicKey [256 + 32]byte

	if c.isClient {
		// If client, send our authenticated public key.
		if err := c.sendBytes(myAuthPublicKey[:]); err != nil {
			return err
		}
	}

	// Receive their authenticated public key.
	if err := c.receiveBytes(theirAuthPublicKey[:]); err != nil {
		return err
	}

	// Check their public key authenticator.
	var sum [32]byte
	h = hmac.New(sha256.New, theirDHMac)
	h.Write(theirAuthPublicKey[0:256])
	if subtle.ConstantTimeCompare(h.Sum(sum[:0]), theirAuthPublicKey[256:]) != 1 {
		return errors.New("gospiped: authentication failed")
	}

	if !c.isClient {
		// If server, send our authenticated public key.
		if err := c.sendBytes(myAuthPublicKey[:]); err != nil {
			return err
		}
	}

	// Calculate DH shared key.
	theirPublicKey := theirAuthPublicKey[:256]
	dhSharedKey, err := dhgroup14.SharedKey(rand.Reader, theirPublicKey, myPrivateKey)
	if err != nil {
		return err
	}

	// Derive final encryption and MAC keys.
	copy(nonces[64:], dhSharedKey)
	dk2 := pbkdf2.Key(c.secretKey, nonces[:], 1, 128, sha256.New)

	eC, hC, eS, hS := dk2[0:32], dk2[32:64], dk2[64:96], dk2[96:128]

	// Set reader and writer depending on our role.
	if c.isClient {
		c.w = newEncryptor(c.conn, eC, hC)
		c.r = newDecryptor(c.conn, eS, hS)
	} else {
		c.w = newEncryptor(c.conn, eS, hS)
		c.r = newDecryptor(c.conn, eC, hC)
	}
	c.handshakePerformed = true
	return nil
}

func (c *connection) Close() error {
	//XXX Flush writer?
	c.r = nil
	c.w = nil
	return c.conn.Close()
}

func (c *connection) Read(p []byte) (nn int, err error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func (c *connection) Write(p []byte) (nn int, err error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	return c.w.Write(p)
}

func (c *connection) Flush() error {
	if err := c.handshake(); err != nil {
		return err
	}
	return c.w.Flush()
}

func secretKeyFromKeyData(keyData []byte) []byte {
	h := sha256.New()
	h.Write(keyData)
	return h.Sum(nil)
}

type ClientConn struct {
	connection
}

// Dial connects to remote address raddr on the given network, which must be
// running spiped server with the same shared secret key. It then performs
// handshake to authenticate itself, and returns the connection on success.
func Dial(key []byte, network, raddr string) (*ClientConn, error) {
	nc, err := net.Dial(network, raddr)
	if err != nil {
		return nil, err
	}
	return Client(key, nc)
}

type Listener struct {
	secretKey []byte
	nl        net.Listener
}

// Listen announces on the local network address laddr, which
// will accept spiped client connections with the given shared
// secret key.
func Listen(key []byte, network, laddr string) (*Listener, error) {
	nl, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &Listener{
		secretKey: secretKeyFromKeyData(key),
		nl:        nl,
	}, nil
}

// Accept waits for and returns the next connection to the listener.
// After accepting the connection, Handshake must be called on it
// to authenticate client.
func (l *Listener) Accept() (c *ServerConn, err error) {
	nc, err := l.nl.Accept()
	if err != nil {
		return nil, err
	}
	return &ServerConn{
		connection: connection{
			conn:      nc,
			secretKey: l.secretKey,
			isClient:  false,
		},
	}, nil
}

func (l *Listener) Close() error {
	return l.nl.Close()
}

func (l *Listener) Addr() net.Addr {
	return l.nl.Addr()
}

type ServerConn struct {
	connection
}

// Handshake runs the server handshake if it has not yet been run.
// Most uses of this package need not call Handshake explicitly: the first Read
// or Write will call it automatically.
func (c *ServerConn) Handshake() error {
	if err := c.handshake(); err != nil {
		return err
	}
	return nil
}

// Client returns a new spiped client connection using nc as the
// underlying connection.
//
// It performs handshake to authenticate.
func Client(key []byte, nc net.Conn) (*ClientConn, error) {
	// Initialize client connection.
	c := &ClientConn{
		connection: connection{
			conn:      nc,
			secretKey: secretKeyFromKeyData(key),
			isClient:  true,
		},
	}
	// Perform handshake.
	if err := c.handshake(); err != nil {
		return nil, err
	}
	return c, nil
}

// Server returns a new spiped server connection using nc as the
// underlying connection.
//
// It performs handshake to authenticate.
func Server(key []byte, nc net.Conn) (*ServerConn, error) {
	c := &ServerConn{
		connection: connection{
			conn:      nc,
			secretKey: secretKeyFromKeyData(key),
			isClient:  false,
		},
	}
	// Perform handshake.
	if err := c.handshake(); err != nil {
		return nil, err
	}
	return c, nil
}
