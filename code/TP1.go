// test799 : project USAG TP1 protocol R5
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

const (
	// Operation Mode
	MODE_MSGONLY uint16 = 0x1

	// Hash Function Mode
	HASH_SHA3 uint16 = 0x10
	HASH_PBK2 uint16 = 0x20
	HASH_ARG2 uint16 = 0x30

	// Symmetric Encryption Mode
	SYM_GCM1  uint16 = 0x100
	SYM_GCMX1 uint16 = 0x200

	// Asymmetric Encryption Mode
	ASYM_RSA1 uint16 = 0x1000
	ASYM_RSA2 uint16 = 0x2000
	ASYM_ECC1 uint16 = 0x3000
	ASYM_PQC1 uint16 = 0x4000

	// Status
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

func DelPath(path string) error {
	err := os.RemoveAll(path) // first try
	if err != nil {
		time.Sleep(1 * time.Second)
		err = os.RemoveAll(path) // second try
	}
	if err != nil {
		time.Sleep(3 * time.Second)
		err = os.RemoveAll(path) // third try
	}
	return err
}

// ========== TP1 Class ==========
type TP1 struct {
	Mode    uint16
	InMem   bool
	DoPad   bool
	SharedS string

	stage int
	sent  uint64
	total uint64
	lock  sync.Mutex
	conn  net.Conn
	magic [4]byte
	zero8 [8]byte
	max8  [8]byte
}

func (p *TP1) Init(mode uint16, inMem bool, doPad bool, shs string, conn net.Conn) {
	p.Mode = mode
	p.InMem = inMem
	p.DoPad = doPad
	p.SharedS = shs
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
	// 1. Generate key pair
	var myPub, myPriv []byte
	var err error
	am := new(Bencrypt.AsymMaster)
	switch p.Mode & 0xF000 {
	case ASYM_RSA1:
		err = am.Init("rsa1")
	case ASYM_RSA2:
		err = am.Init("rsa2")
	case ASYM_ECC1:
		err = am.Init("ecc1")
	case ASYM_PQC1:
		err = am.Init("pqc1")
	default:
		err = errors.New("invalid mode: no valid algorithm flag set")
	}
	if err == nil {
		myPub, myPriv, err = am.Genkey()
	}
	if err != nil {
		return nil, nil, nil, err
	}

	// 2. Send init packet: Magic(4B) + Mode(2B)
	initPkt := make([]byte, 6)
	copy(initPkt[0:4], p.magic[:])
	copy(initPkt[4:6], Opsec.EncodeInt(uint64(p.Mode), 2))
	if _, err := p.conn.Write(initPkt); err != nil {
		return nil, nil, nil, err
	}

	// 3. Send Sender Auth: Nonce(8B) + Hash(32B)
	nonce := Bencrypt.Random(8)
	hm := new(Bencrypt.HashMaster)
	switch p.Mode & 0xF0 {
	case HASH_SHA3:
		err = hm.Init("sha3", 32, 44)
	case HASH_PBK2:
		err = hm.Init("pbk2", 32, 44)
	case HASH_ARG2:
		err = hm.Init("arg2", 32, 44)
	default:
		err = errors.New("invalid mode: no valid algorithm flag set")
	}
	if err != nil {
		return nil, nil, nil, err
	}

	hashSrc := make([]byte, 0, len(myPub)+len(p.SharedS)) // myPub + SharedS
	hashSrc = append(hashSrc, myPub...)
	hashSrc = append(hashSrc, []byte(p.SharedS)...)
	hash, _, err := hm.KDF(hashSrc, nonce)
	if err != nil {
		return nil, nil, nil, err
	}

	authPkt := make([]byte, 40) // 8 + 32
	copy(authPkt[0:8], nonce)
	copy(authPkt[8:40], hash)
	if _, err := p.conn.Write(authPkt); err != nil {
		return nil, nil, nil, err
	}

	// 4. Receive Receiver Auth: Nonce(8B) + Hash(32B)
	peerAuth := make([]byte, 40)
	if _, err := io.ReadFull(p.conn, peerAuth); err != nil {
		return nil, nil, nil, err
	}
	peerNonce := peerAuth[0:8]
	peerHash := peerAuth[8:40]

	// 5. Send Sender PubKey: Length(2B) + PubKey
	pubLen := len(myPub)
	if pubLen > 65535 {
		return nil, nil, nil, errors.New("public key is too long")
	}
	pubPkt := make([]byte, 2+pubLen)
	copy(pubPkt[0:2], Opsec.EncodeInt(uint64(pubLen), 2))
	copy(pubPkt[2:], myPub)
	if _, err := p.conn.Write(pubPkt); err != nil {
		return nil, nil, nil, err
	}

	// 6. Receive Receiver PubKey: Length(2B) + PubKey
	head := make([]byte, 2)
	if _, err := io.ReadFull(p.conn, head); err != nil {
		return nil, nil, nil, err
	}
	peerPubLen := Opsec.DecodeInt(head)
	peerPub := make([]byte, int(peerPubLen))
	if _, err := io.ReadFull(p.conn, peerPub); err != nil {
		return nil, nil, nil, err
	}

	// 7. Verify Receiver Auth
	verifySrc := make([]byte, 0, len(peerPub)+len(p.SharedS)) // peerPub + SharedS
	verifySrc = append(verifySrc, peerPub...)
	verifySrc = append(verifySrc, []byte(p.SharedS)...)
	verifyHash, _, err := hm.KDF(verifySrc, peerNonce)
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(peerHash, verifyHash) {
		return nil, nil, nil, errors.New("receiver authentication failed")
	}
	return peerPub, myPub, myPriv, nil
}

// handshake with sender, returns (peer public key, my public key, my private key)
func (p *TP1) handshakeReceive() ([]byte, []byte, []byte, error) {
	// 1. Receive init packet: Magic(4B) + Mode(2B)
	header := make([]byte, 6)
	if _, err := io.ReadFull(p.conn, header); err != nil {
		return nil, nil, nil, err
	}
	if string(header[:4]) != string(p.magic[:]) { // Validate Magic
		return nil, nil, nil, errors.New("invalid magic number")
	}
	p.Mode = uint16(Opsec.DecodeInt(header[4:6])) // Parse Mode

	// 2. Generate key pair based on Mode
	var myPub, myPriv []byte
	var err error
	am := new(Bencrypt.AsymMaster)
	switch p.Mode & 0xF000 {
	case ASYM_RSA1:
		err = am.Init("rsa1")
	case ASYM_RSA2:
		err = am.Init("rsa2")
	case ASYM_ECC1:
		err = am.Init("ecc1")
	case ASYM_PQC1:
		err = am.Init("pqc1")
	default:
		return nil, nil, nil, errors.New("invalid mode: no valid algorithm flag set")
	}
	if err != nil {
		return nil, nil, nil, err
	}
	myPub, myPriv, err = am.Genkey()
	if err != nil {
		return nil, nil, nil, err
	}

	// 3. Receive Sender Auth: Nonce(8B) + Hash(32B)
	peerAuth := make([]byte, 40)
	if _, err := io.ReadFull(p.conn, peerAuth); err != nil {
		return nil, nil, nil, err
	}
	peerNonce := peerAuth[0:8]
	peerHash := peerAuth[8:40]

	// 4. Initialize HashMaster based on received Mode
	hm := new(Bencrypt.HashMaster)
	switch p.Mode & 0xF0 {
	case HASH_SHA3:
		err = hm.Init("sha3", 32, 44)
	case HASH_PBK2:
		err = hm.Init("pbk2", 32, 44)
	case HASH_ARG2:
		err = hm.Init("arg2", 32, 44)
	default:
		return nil, nil, nil, errors.New("invalid mode: no valid hash algorithm flag set")
	}
	if err != nil {
		return nil, nil, nil, err
	}

	// 5. Send Receiver Auth: Nonce(8B) + Hash(32B)
	myNonce := Bencrypt.Random(8)
	hashSrc := make([]byte, 0, len(myPub)+len(p.SharedS)) // myPub + SharedS
	hashSrc = append(hashSrc, myPub...)
	hashSrc = append(hashSrc, []byte(p.SharedS)...)
	myHash, _, err := hm.KDF(hashSrc, myNonce)
	if err != nil {
		return nil, nil, nil, err
	}

	authPkt := make([]byte, 40) // 8 + 32
	copy(authPkt[0:8], myNonce)
	copy(authPkt[8:40], myHash)
	if _, err := p.conn.Write(authPkt); err != nil {
		return nil, nil, nil, err
	}

	// 6. Receive Sender PubKey: Length(2B) + PubKey
	head := make([]byte, 2)
	if _, err := io.ReadFull(p.conn, head); err != nil {
		return nil, nil, nil, err
	}
	peerPubLen := Opsec.DecodeInt(head)
	peerPub := make([]byte, int(peerPubLen))
	if _, err := io.ReadFull(p.conn, peerPub); err != nil {
		return nil, nil, nil, err
	}

	// 7. Send Receiver PubKey: Length(2B) + PubKey
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

	// 8. Verify Sender Auth
	verifySrc := make([]byte, 0, len(peerPub)+len(p.SharedS)) // peerPub + SharedS
	verifySrc = append(verifySrc, peerPub...)
	verifySrc = append(verifySrc, []byte(p.SharedS)...)
	verifyHash, _, err := hm.KDF(verifySrc, peerNonce)
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(peerHash, verifyHash) {
		return nil, nil, nil, errors.New("sender authentication failed")
	}
	return peerPub, myPub, myPriv, nil
}

// Send data, public key is [from, to]
func (p *TP1) Send(src io.Reader, size int64, smsg string) ([]byte, []byte, error) {
	// 1. Handshake
	p.setStage(STAGE_HANDSHAKE)
	p.conn.SetDeadline(time.Now().Add(30 * time.Second)) // set deadline for handshake
	peerPub, myPub, myPriv, err := p.handshakeSend()
	p.conn.SetDeadline(time.Time{}) // clear deadline
	if err != nil {
		p.setStage(STAGE_ERROR)
		return myPub, peerPub, err
	}
	stop := make(chan bool)
	go p.syncStatus(stop)
	p.setStage(STAGE_ENCRYPTING)

	// 2. Prepare encryption worker
	sm := new(Bencrypt.SymMaster)
	switch p.Mode & 0xF00 {
	case SYM_GCM1:
		err = sm.Init("gcm1", make([]byte, 44))
	case SYM_GCMX1:
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
	ops.Smsg = smsg
	ops.SmsgInfo = []byte(p.SharedS)
	ops.BodyAlgo = sm.Algo
	ops.BodySize = sm.AfterSize(size)
	var opsHead []byte
	switch p.Mode & 0xF000 {
	case ASYM_RSA1:
		opsHead, err = ops.Encpub("rsa1", peerPub, myPriv)
	case ASYM_RSA2:
		opsHead, err = ops.Encpub("rsa2", peerPub, myPriv)
	case ASYM_ECC1:
		opsHead, err = ops.Encpub("ecc1", peerPub, myPriv)
	case ASYM_PQC1:
		opsHead, err = ops.Encpub("pqc1", peerPub, myPriv)
	default:
		err = errors.New("invalid mode: no valid algorithm flag set")
	}
	if err == nil {
		err = sm.Init(sm.Algo, ops.BodyKey) // set body key
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
		defer DelPath(tempPath)
		defer f.Close()
		tempFile = f
		tempWriter = f
	}

	// 5. Write Opsec Header, Body, Padding
	var writed int64 = 0
	writed += int64(len(opsHead)) + 6 // opsec magic
	if len(opsHead) >= 65535 {
		writed += 2
	}
	if err := ops.Write(tempWriter, opsHead); err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return myPub, peerPub, err
	}
	writed += ops.BodySize
	if err := sm.EnFile(src, size, tempWriter); err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return myPub, peerPub, err
	}
	if p.DoPad {
		padLen := Opsec.PadLen(writed)
		err = Opsec.PadFile(tempWriter, padLen)
		if err != nil {
			p.setStage(STAGE_ERROR)
			stop <- false
			return myPub, peerPub, err
		}
		writed += padLen
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
	buf := make([]byte, 32768)
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
	p.conn.SetDeadline(time.Now().Add(30 * time.Second)) // set deadline for handshake
	peerPub, myPub, myPriv, err := p.handshakeReceive()
	p.conn.SetDeadline(time.Time{}) // clear deadline
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
		defer DelPath(tempPath)
		defer f.Close()
		tempFile = f
		tempWriter = f
	}

	// 3-1. Stream Receive
	p.setSent(0)
	buf := make([]byte, 32768)
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
	if err := ops.Decpub(myPriv, myPub, peerPub); err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, "", err
	}
	if !bytes.Equal(ops.SmsgInfo, []byte(p.SharedS)) {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, "", errors.New("invalid session shared secret")
	}

	// 6. Prepare decryption worker
	p.setStage(STAGE_ENCRYPTING)
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init(ops.BodyAlgo, ops.BodyKey); err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, "", err
	}

	// 7. Decrypt Body to Stream
	if err := sm.DeFile(tempReader, ops.BodySize, dst); err != nil {
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
