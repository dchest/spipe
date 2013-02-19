// Package spipe implements Colin Percival's spiped protocol
// (http://www.tarsnap.com/spiped.html) for creating symmetrically
// encrypted and authenticated connections.
//
// Communication between client and server requires a pre-shared symmetric key
// with at least 256 bits of entropy. The initial key negotiation is performed
// using HMAC-SHA256 and an authenticated Diffie-Hellman key exchange over the
// standard 2048-bit "group 14". Packets are transmitted encrypted with AES-256
// in CTR mode and authenticated using HMAC-SHA256.
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
//
// Shared key can be of any length, as it is compressed with SHA256 before
// using.
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
		panic("spipe: " + err.Error())
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
		return errors.New("spipe: wrote partial packet")
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
		panic("spipe: " + err.Error())
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
		return errors.New("spipe: failed to authenticate packet")
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
		return errors.New("spipe: message length is too large")
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

type Conn struct {
	w *encryptor
	r *decryptor

	isClient  bool
	secretKey []byte

	handshakeMutex     sync.Mutex
	handshakePerformed bool

	conn net.Conn // underlying connection
}

func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

func (c *Conn) sendBytes(p []byte) error {
	n, err := c.conn.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return errors.New("spipe: partial write")
	}
	return nil
}

func (c *Conn) receiveBytes(p []byte) error {
	if _, err := io.ReadFull(c.conn, p); err != nil {
		return err
	}
	return nil
}

// Handshake runs handshake if it has not yet been run. Most users of this
// package need not call Handshake explicitly: the first Read or Write will
// call it automatically.
func (c *Conn) Handshake() error {
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
		return errors.New("spipe: authentication failed")
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

func (c *Conn) Close() error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	//XXX Flush writer?
	c.handshakePerformed = false
	c.r = nil
	c.w = nil
	return c.conn.Close()
}

func (c *Conn) Read(p []byte) (nn int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

func (c *Conn) Write(p []byte) (nn int, err error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	return c.w.Write(p)
}

func (c *Conn) Flush() error {
	if err := c.Handshake(); err != nil {
		return err
	}
	return c.w.Flush()
}

func secretKeyFromKeyData(keyData []byte) []byte {
	h := sha256.New()
	h.Write(keyData)
	return h.Sum(nil)
}

// Dial connects to remote address raddr on the given network, which must be
// running spipe server with the same shared secret key. It then performs
// handshake to authenticate itself, and returns the connection on success.
func Dial(key []byte, network, raddr string) (*Conn, error) {
	nc, err := net.Dial(network, raddr)
	if err != nil {
		return nil, err
	}
	c := Client(key, nc)
	// Perform handshake.
	if err := c.Handshake(); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

type listener struct {
	net.Listener
	secretKey []byte
}

// Listen announces on the local network address laddr, which
// will accept spipe client connections with the given shared
// secret key.
func Listen(key []byte, network, laddr string) (net.Listener, error) {
	nl, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &listener{
		Listener:  nl,
		secretKey: secretKeyFromKeyData(key),
	}, nil
}

// Accept waits for and returns the next connection to the listener.
// The returned connection c is a *spipe.Conn.
func (l *listener) Accept() (c net.Conn, err error) {
	nc, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &Conn{
		conn:      nc,
		secretKey: l.secretKey,
		isClient:  false,
	}, nil
}

// Client returns a new spipe client connection using nc as the
// underlying connection.
func Client(key []byte, nc net.Conn) *Conn {
	return &Conn{
		conn:      nc,
		secretKey: secretKeyFromKeyData(key),
		isClient:  true,
	}
}

// Server returns a new spipe server connection using nc as the
// underlying connection.
func Server(key []byte, nc net.Conn) *Conn {
	return &Conn{
		conn:      nc,
		secretKey: secretKeyFromKeyData(key),
		isClient:  false,
	}
}
