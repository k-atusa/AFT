// test799 : project USAG TP1 protocol
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Opsec"
)

// Mode Flags
const (
	MODE_MSGONLY uint16 = 0x1

	MODE_GCM1  uint16 = 0x10
	MODE_GCMX1 uint16 = 0x20

	MODE_RSA1_2K uint16 = 0x100
	MODE_RSA1_3K uint16 = 0x200
	MODE_RSA1_4K uint16 = 0x400
	MODE_ECC1    uint16 = 0x800

	STAGE_IDLE         int = 0
	STAGE_HANDSHAKE    int = 1
	STAGE_ENCRYPTING   int = 2
	STAGE_TRANSFERRING int = 3
	STAGE_COMPLETE     int = 4
	STAGE_ERROR        int = -1
)

// ========== Helper Functions ==========
func GetIPs(v4only bool) ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	res := make([]string, 0)
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() { // skip loopback
			if v4only && ipnet.IP.To4() == nil {
				continue
			}
			res = append(res, ipnet.IP.String())
		}
	}
	return res, nil
}

func GetPath() string {
	exePath, err := os.Executable()
	if err != nil {
		return "./"
	}
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		realPath = exePath
	}
	return filepath.Dir(realPath)
}

func CleanPath(path string) string {
	replaceChars := []string{"\\", "/", ":", "*", "?", "\"", "<", ">", "|"}
	for _, char := range replaceChars {
		path = strings.ReplaceAll(path, char, "_")
	}
	return path
}

func TempPath() string {
	path := filepath.Join(GetPath(), hex.EncodeToString(Bencrypt.Random(6))+".temp")
	for {
		if _, err := os.Stat(path); err == nil {
			path = filepath.Join(GetPath(), hex.EncodeToString(Bencrypt.Random(6))+".temp")
		} else {
			break
		}
	}
	return path
}

// ========== TP1 Class ==========
type TP1 struct {
	Mode  uint16
	InMem bool

	stage int
	sent  uint64
	total uint64
	lock  sync.Mutex
	conn  net.Conn
	magic [4]byte
	zero8 [8]byte
	max8  [8]byte
}

func (p *TP1) Init(mode uint16, InMem bool, conn net.Conn) {
	p.Mode = mode
	p.InMem = InMem
	p.stage = 0
	p.sent = 0
	p.total = 0
	p.conn = conn
	p.magic = [4]byte{'U', 'T', 'P', '1'}
	p.zero8 = [8]byte{0, 0, 0, 0, 0, 0, 0, 0}
	p.max8 = [8]byte{255, 255, 255, 255, 255, 255, 255, 255}
}

func (p *TP1) GetStatus() (int, uint64, uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.stage, p.sent, p.total
}

func (p *TP1) setStage(stage int) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.stage = stage
}

func (p *TP1) setSent(sent uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.sent = sent
}

func (p *TP1) setTotal(total uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.total = total
}

func (p *TP1) syncStatus(stop chan bool) {
	defer func() {
		close(stop)
		if err := recover(); err != nil {
			p.setStage(STAGE_ERROR)
		}
	}()
	for {
		select {
		case s := <-stop:
			if !s {
				p.conn.Write(p.max8[:])
			}
			return
		case <-time.After(1 * time.Second):
			p.conn.Write(p.zero8[:])
		}
	}
}

// handshake with receiver, returns (peer public key, my public key, my private key)
func (p *TP1) handshakeSend() ([]byte, []byte, []byte, error) {
	// 1. Make key pair
	var myPub, myPriv []byte
	var err error
	am := new(Bencrypt.AsymMaster)
	switch {
	case p.Mode&MODE_RSA1_2K != 0:
		err = am.Init("rsa1-2k")
	case p.Mode&MODE_RSA1_3K != 0:
		err = am.Init("rsa1-3k")
	case p.Mode&MODE_RSA1_4K != 0:
		err = am.Init("rsa1-4k")
	case p.Mode&MODE_ECC1 != 0:
		err = am.Init("ecc1")
	default:
		err = errors.New("invalid mode: no valid algorithm flag set")
	}
	if err == nil {
		myPub, myPriv, err = am.Genkey()
	}
	if err != nil {
		p.setStage(STAGE_ERROR)
		return nil, nil, nil, err
	}

	// 2. Prepare Packet: Magic(4) + Mode(2) + PubSize(2) + PubKey(N)
	buf := make([]byte, 8+len(myPub))
	copy(buf[0:4], p.magic[:])
	pubLen := len(myPub)
	if pubLen > 65535 {
		return nil, nil, nil, errors.New("public key is too long")
	}
	copy(buf[4:6], Opsec.EncodeInt(uint64(p.Mode), 2))
	copy(buf[6:8], Opsec.EncodeInt(uint64(pubLen), 2))
	copy(buf[8:], myPub)

	// 3. Send Packet
	if _, err := p.conn.Write(buf); err != nil {
		return nil, nil, nil, err
	}

	// 4. Receive Response: PubSize(2) + PubKey(M)
	head := make([]byte, 2)
	if _, err := io.ReadFull(p.conn, head); err != nil {
		return nil, nil, nil, err
	}
	peerPubLen := Opsec.DecodeInt(head)
	peerPub := make([]byte, int(peerPubLen))
	if _, err := io.ReadFull(p.conn, peerPub); err != nil {
		return nil, nil, nil, err
	}
	return peerPub, myPub, myPriv, nil
}

// handshake with sender, returns (peer public key, my public key, my private key)
func (p *TP1) handshakeReceive() ([]byte, []byte, []byte, error) {
	// 1. Receive Packet: Magic(4) + Mode(2) + PubSize(2)
	header := make([]byte, 8)
	if _, err := io.ReadFull(p.conn, header); err != nil {
		return nil, nil, nil, err
	}

	// 2. Validate Magic
	if string(header[:4]) != string(p.magic[:]) {
		return nil, nil, nil, errors.New("invalid magic number")
	}

	// 3. Parse Mode & Peer PubKey Length
	p.Mode = uint16(Opsec.DecodeInt(header[4:6])) // Mode (2B)
	peerPubLen := Opsec.DecodeInt(header[6:8])    // PubSize (2B)

	// 4. Receive Peer Public Key
	peerPub := make([]byte, peerPubLen)
	if _, err := io.ReadFull(p.conn, peerPub); err != nil {
		return nil, nil, nil, err
	}

	// 5. Generate My Key Pair based on Mode
	var myPub, myPriv []byte
	var err error
	am := new(Bencrypt.AsymMaster)
	switch {
	case p.Mode&MODE_RSA1_2K != 0:
		err = am.Init("rsa1-2k")
	case p.Mode&MODE_RSA1_3K != 0:
		err = am.Init("rsa1-3k")
	case p.Mode&MODE_RSA1_4K != 0:
		err = am.Init("rsa1-4k")
	case p.Mode&MODE_ECC1 != 0:
		err = am.Init("ecc1")
	default:
		err = errors.New("invalid mode: no valid algorithm flag set")
	}
	if err == nil {
		myPub, myPriv, err = am.Genkey()
	}
	if err != nil {
		p.setStage(STAGE_ERROR)
		return nil, nil, nil, err
	}

	// 6. Send Response: PubSize(2) + PubKey(M)
	myPubLen := len(myPub)
	if myPubLen > 65535 {
		return nil, nil, nil, errors.New("generated public key is too long")
	}
	resp := make([]byte, 2+myPubLen)
	copy(resp[0:2], Opsec.EncodeInt(uint64(myPubLen), 2))
	copy(resp[2:], myPub)
	if _, err := p.conn.Write(resp); err != nil {
		return nil, nil, nil, err
	}
	return peerPub, myPub, myPriv, nil
}

// Send data, public key is [from, to]
func (p *TP1) Send(src io.Reader, size int64, smsg string) ([]byte, []byte, error) {
	// 1. Handshake
	p.setStage(STAGE_HANDSHAKE)
	peerPub, myPub, myPriv, err := p.handshakeSend()
	if err != nil {
		return myPub, peerPub, err
	}
	stop := make(chan bool)
	go p.syncStatus(stop)
	p.setStage(STAGE_ENCRYPTING)

	// 2. Prepare encryption worker
	sm := new(Bencrypt.SymMaster)
	switch {
	case p.Mode&MODE_GCM1 != 0:
		err = sm.Init("gcm1", make([]byte, 44))
	case p.Mode&MODE_GCMX1 != 0:
		err = sm.Init("gcmx1", make([]byte, 44))
	default:
		err = errors.New("invalid mode: no valid algorithm flag set")
	}
	if err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return myPub, peerPub, err
	}

	// 3. Prepare Opsec Header, set Body Key
	ops := new(Opsec.Opsec)
	ops.Reset()
	ops.Size = sm.AfterSize(size)
	ops.BodyAlgo = sm.Algo
	ops.Smsg = smsg
	var opsHead []byte
	switch {
	case p.Mode&MODE_RSA1_2K != 0, p.Mode&MODE_RSA1_3K != 0, p.Mode&MODE_RSA1_4K != 0:
		opsHead, err = ops.Encpub("rsa1", peerPub, myPriv)
	case p.Mode&MODE_ECC1 != 0:
		opsHead, err = ops.Encpub("ecc1", peerPub, myPriv)
	default:
		err = errors.New("invalid mode: no valid algorithm flag set")
	}
	if err == nil {
		err = sm.Init(sm.Algo, ops.BodyKey)
	}
	if err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return myPub, peerPub, err
	}

	// 4. Prepare Temp File
	var tempWriter io.Writer
	var tempFile *os.File
	var memBuf *bytes.Buffer
	if p.InMem {
		memBuf = new(bytes.Buffer)
		tempWriter = memBuf
	} else {
		tempPath := TempPath()
		f, err := os.Create(tempPath)
		if err != nil {
			p.setStage(STAGE_ERROR)
			stop <- false
			return myPub, peerPub, err
		}
		defer os.Remove(tempPath)
		defer f.Close()
		tempFile = f
		tempWriter = f
	}

	// 5. Write Opsec Header, Body
	if err := ops.Write(tempWriter, opsHead); err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return myPub, peerPub, err
	}
	if err := sm.EnFile(src, size, tempWriter); err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return myPub, peerPub, err
	}

	// 6. Transfer the Entire Temp Data
	p.setStage(STAGE_TRANSFERRING)
	stop <- true
	var tempReader io.Reader
	var totalSize uint64

	// 6-1. Prepare Temp Reader
	if p.InMem {
		totalSize = uint64(memBuf.Len())
		tempReader = bytes.NewReader(memBuf.Bytes())
	} else {
		tempInfo, err := tempFile.Stat()
		if err != nil {
			p.setStage(STAGE_ERROR)
			return myPub, peerPub, err
		}
		totalSize = uint64(tempInfo.Size())
		if _, err := tempFile.Seek(0, 0); err != nil {
			p.setStage(STAGE_ERROR)
			return myPub, peerPub, err
		}
		tempReader = tempFile
	}

	// 6-2. Send Total Size Packet
	p.setSent(0)
	p.setTotal(totalSize)
	if _, err := p.conn.Write(Opsec.EncodeInt(totalSize, 8)); err != nil {
		p.setStage(STAGE_ERROR)
		return myPub, peerPub, err
	}

	// 6-4. Stream Send
	buf := make([]byte, 1024)
	var currentSent uint64 = 0
	for {
		nr, rErr := tempReader.Read(buf)
		if nr > 0 {
			nw, wErr := p.conn.Write(buf[0:nr])
			if wErr != nil {
				p.setStage(STAGE_ERROR)
				return myPub, peerPub, wErr
			}
			currentSent += uint64(nw)
			p.setSent(currentSent)
		}
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			p.setStage(STAGE_ERROR)
			return myPub, peerPub, rErr
		}
	}

	// 7. Receive Termination
	var term [8]byte
	if _, err := io.ReadFull(p.conn, term[:]); err != nil {
		p.setStage(STAGE_ERROR)
		return myPub, peerPub, err
	}
	if term != p.zero8 {
		p.setStage(STAGE_ERROR)
		return myPub, peerPub, errors.New("abnormal termination signal")
	}
	p.setStage(STAGE_COMPLETE)
	return myPub, peerPub, nil
}

// Receive data, public key is [from, to]
func (p *TP1) Receive(dst io.Writer) ([]byte, []byte, string, error) {
	// 1. Handshake
	p.setStage(STAGE_HANDSHAKE)
	peerPub, myPub, myPriv, err := p.handshakeReceive()
	if err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, "", err
	}

	// 2. Wait for Status (Start Signal)
	p.setStage(STAGE_TRANSFERRING)
	var buf8 [8]byte
	var totalSize uint64
	for {
		if _, err := io.ReadFull(p.conn, buf8[:]); err != nil {
			p.setStage(STAGE_ERROR)
			return peerPub, myPub, "", err
		}
		if buf8 == p.zero8 {
			continue // Still preparing
		} else if buf8 == p.max8 {
			p.setStage(STAGE_ERROR)
			return peerPub, myPub, "", errors.New("remote error reported")
		} else {
			totalSize = Opsec.DecodeInt(buf8[:])
			p.setTotal(totalSize) // Total transmission size (Header + Body)
			break                 // Start transfer
		}
	}

	// 3. Download Stream to Temp Storage
	var tempWriter io.Writer
	var tempFile *os.File
	var memBuf *bytes.Buffer
	if p.InMem {
		memBuf = new(bytes.Buffer)
		tempWriter = memBuf
	} else {
		tempPath := TempPath()
		f, err := os.Create(tempPath)
		if err != nil {
			p.setStage(STAGE_ERROR)
			return peerPub, myPub, "", err
		}
		defer os.Remove(tempPath)
		defer f.Close()
		tempFile = f
		tempWriter = f
	}

	// 3-1. Stream Receive
	p.setSent(0)
	buf := make([]byte, 1024)
	var currentReceived uint64 = 0
	for currentReceived < totalSize {
		remaining := totalSize - currentReceived
		toRead := min(remaining, uint64(len(buf)))

		n, rErr := p.conn.Read(buf[:toRead])
		if n > 0 {
			if _, wErr := tempWriter.Write(buf[:n]); wErr != nil {
				p.setStage(STAGE_ERROR)
				return peerPub, myPub, "", wErr
			}
			currentReceived += uint64(n)
			p.setSent(currentReceived)
		}

		if currentReceived == totalSize {
			break
		}
		if rErr != nil {
			if rErr == io.EOF && currentReceived == totalSize {
				break
			}
			p.setStage(STAGE_ERROR)
			return peerPub, myPub, "", rErr
		}
	}

	// 4. Send Termination
	if _, err := p.conn.Write(p.zero8[:]); err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, "", err
	}

	// 5. Decrypt Header
	var tempReader io.Reader
	if p.InMem {
		tempReader = bytes.NewReader(memBuf.Bytes())
	} else {
		if _, err := tempFile.Seek(0, 0); err != nil {
			p.setStage(STAGE_ERROR)
			return peerPub, myPub, "", err
		}
		tempReader = tempFile
	}
	ops := new(Opsec.Opsec)
	headBytes, err := ops.Read(tempReader, 0)
	if err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, "", err
	}
	ops.View(headBytes)
	if err := ops.Decpub(myPriv, peerPub); err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, "", err
	}

	// 6. Prepare decryption worker
	p.setStage(STAGE_ENCRYPTING)
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init(ops.BodyAlgo, ops.BodyKey); err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, "", err
	}

	// 7. Decrypt Body to Stream
	if err := sm.DeFile(tempReader, ops.Size, dst); err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, "", err
	}
	p.setStage(STAGE_COMPLETE)
	return peerPub, myPub, ops.Smsg, nil
}

// ========== Make TCP Socket ==========
type TCPsocket struct {
	Listener net.Listener
	Conn     net.Conn
}

func (t *TCPsocket) MakeListener(port string) (err error) {
	t.Listener = nil
	t.Conn = nil
	t.Listener, err = net.Listen("tcp", ":"+port)
	if err != nil {
		return err
	}
	t.Listener.(*net.TCPListener).SetDeadline(time.Now().Add(90 * time.Second)) // 90s timeout
	conn, err := t.Listener.Accept()
	if err != nil {
		return err
	}
	t.Conn = conn
	return nil
}

func (t *TCPsocket) MakeConnection(addr string) (err error) {
	t.Listener = nil
	t.Conn = nil
	for range 5 { // 5 attempts, 10s timeout, 3s interval
		t.Conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
		if err == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		return err
	}
	return nil
}

func (t *TCPsocket) Close() {
	if t.Conn != nil {
		t.Conn.Close()
	}
	if t.Listener != nil {
		t.Listener.Close()
	}
}
