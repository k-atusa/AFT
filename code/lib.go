// test798a : project USAG AFT-desktop library [Refer: @k-atusa/YAS-desktop]
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/k-atusa/USAG-Lib/Bencode"
	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Icons"
	"github.com/k-atusa/USAG-Lib/Opsec"
)

// get local IPs
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

// Mode Flags
const (
	MODE_MSGONLY uint16 = 0x1
	MODE_LEGACY  uint16 = 0x2 // for RSA
	MODE_RSA_4K  uint16 = 0x4 // for RSA

	STAGE_IDLE         int = 0
	STAGE_HANDSHAKE    int = 1
	STAGE_ENCRYPTING   int = 2
	STAGE_TRANSFERRING int = 3
	STAGE_COMPLETE     int = 4
	STAGE_ERROR        int = -1
)

type TPprotocol struct {
	Mode  uint16
	stage int
	sent  uint64
	total uint64
	lock  sync.Mutex
	conn  net.Conn
	magic [4]byte
	zero8 [8]byte
	max8  [8]byte
}

func (p *TPprotocol) Init(mode uint16, conn net.Conn) {
	p.Mode = mode
	p.stage = 0
	p.sent = 0
	p.total = 0
	p.conn = conn
	p.magic = [4]byte{'U', 'T', 'P', '1'}
	p.zero8 = [8]byte{0, 0, 0, 0, 0, 0, 0, 0}
	p.max8 = [8]byte{255, 255, 255, 255, 255, 255, 255, 255}
}

func (p *TPprotocol) GetStatus() (int, uint64, uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()
	return p.stage, p.sent, p.total
}

func (p *TPprotocol) setStage(stage int) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.stage = stage
}

func (p *TPprotocol) setSent(sent uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.sent = sent
}

func (p *TPprotocol) setTotal(total uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.total = total
}

func (p *TPprotocol) syncStatus(stop chan bool) {
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
func (p *TPprotocol) handshakeSend() ([]byte, []byte, []byte, error) {
	// 1. Make key pair
	var myPub, myPriv []byte
	var err error
	if p.Mode&MODE_LEGACY != 0 {
		r := new(Bencrypt.RSA1)
		if p.Mode&MODE_RSA_4K != 0 {
			myPub, myPriv, err = r.Genkey(4096)
		} else {
			myPub, myPriv, err = r.Genkey(2048)
		}
	} else {
		e := new(Bencrypt.ECC1)
		myPub, myPriv, err = e.Genkey()
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
func (p *TPprotocol) handshakeReceive() ([]byte, []byte, []byte, error) {
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
	if p.Mode&MODE_LEGACY != 0 {
		r := new(Bencrypt.RSA1)
		if p.Mode&MODE_RSA_4K != 0 {
			myPub, myPriv, err = r.Genkey(4096)
		} else {
			myPub, myPriv, err = r.Genkey(2048)
		}
	} else {
		e := new(Bencrypt.ECC1)
		myPub, myPriv, err = e.Genkey()
	}
	if err != nil {
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

// Send memory data, public key is [from, to]
func (p *TPprotocol) SendData(data []byte, smsg string) ([]byte, []byte, error) {
	// 1. Handshake
	p.setStage(STAGE_HANDSHAKE)
	peerPub, myPub, myPriv, err := p.handshakeSend()
	if err != nil {
		return myPub, peerPub, err
	}
	stop := make(chan bool)
	go p.syncStatus(stop)

	// 2. Make Opsec Header
	p.setStage(STAGE_ENCRYPTING)
	ops := new(Opsec.Opsec)
	ops.Reset()
	ops.Size = int64(len(data)) + 16 // data + tag
	ops.BodyAlgo = "gcm1"
	ops.Smsg = smsg

	var opsHead []byte
	if p.Mode&MODE_LEGACY != 0 {
		opsHead, err = ops.Encpub("rsa1", peerPub, myPriv)
	} else {
		opsHead, err = ops.Encpub("ecc1", peerPub, myPriv)
	}
	if err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return myPub, peerPub, err
	}

	// 3. Encrypt body
	aes := new(Bencrypt.AES1)
	var key [44]byte
	copy(key[:], ops.BodyKey)
	encBody, err := aes.EnAESGCM(key, data)
	if err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return myPub, peerPub, err
	}

	// 4. Build Payload with Framing
	var headerBuf bytes.Buffer
	if err := ops.Write(&headerBuf, opsHead); err != nil {
		p.setStage(STAGE_ERROR)
		stop <- false
		return myPub, peerPub, err
	}
	payload := append(headerBuf.Bytes(), encBody...)
	encBody = nil
	totalSize := uint64(len(payload))
	stop <- true
	p.setStage(STAGE_TRANSFERRING)

	// 5. send total size
	p.setSent(0)
	p.setTotal(totalSize)
	if _, err := p.conn.Write(Opsec.EncodeInt(totalSize, 8)); err != nil {
		p.setStage(STAGE_ERROR)
		return myPub, peerPub, err
	}

	// 6. send payload
	var currentSent uint64 = 0
	for currentSent < totalSize {
		n, err := p.conn.Write(payload[currentSent:min(currentSent+1024, totalSize)])
		if err != nil {
			p.setStage(STAGE_ERROR)
			return myPub, peerPub, err
		}
		currentSent += uint64(n)
		p.setSent(currentSent)
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

// Receive to memory data, public key is [from, to]
func (p *TPprotocol) ReceiveData() ([]byte, []byte, []byte, string, error) {
	// 1. Handshake
	p.setStage(STAGE_HANDSHAKE)
	peerPub, myPub, myPriv, err := p.handshakeReceive()
	if err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, nil, "", err
	}

	// 2. Wait for Status (Start Signal)
	p.setStage(STAGE_TRANSFERRING)
	var buf8 [8]byte
	var totalSize uint64
	for {
		if _, err := io.ReadFull(p.conn, buf8[:]); err != nil {
			p.setStage(STAGE_ERROR)
			return peerPub, myPub, nil, "", err
		}

		if buf8 == p.zero8 {
			continue // Still preparing
		} else if buf8 == p.max8 {
			p.setStage(STAGE_ERROR)
			return peerPub, myPub, nil, "", errors.New("remote error reported")
		} else {
			totalSize = Opsec.DecodeInt(buf8[:])
			p.setTotal(totalSize) // Total transmission size (Header + Body)
			break                 // Start transfer
		}
	}

	// 3. Receive All Data to Memory
	payload := make([]byte, totalSize)
	var currentReceived uint64 = 0
	for currentReceived < totalSize {
		n, err := p.conn.Read(payload[currentReceived:])
		if n > 0 {
			currentReceived += uint64(n)
			p.setSent(currentReceived)
		}
		if currentReceived == totalSize {
			break
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			p.setStage(STAGE_ERROR)
			return peerPub, myPub, nil, "", err
		}
	}

	// 4. Send Termination
	if _, err := p.conn.Write(p.zero8[:]); err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, nil, "", err
	}

	// 5. Parse & Decrypt Header
	bufReader := bytes.NewReader(payload)
	ops := new(Opsec.Opsec)
	headBytes, err := ops.Read(bufReader, 0)
	if err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, nil, "", err
	}
	ops.View(headBytes)
	if err := ops.Decpub(myPriv, peerPub); err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, nil, "", err
	}

	// 6. Decrypt Body
	p.setStage(STAGE_ENCRYPTING)
	bodyOffset := totalSize - uint64(bufReader.Len())
	encBody := payload[bodyOffset:]
	if ops.BodyAlgo != "gcm1" {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, nil, "", errors.New("unsupported body algorithm: " + ops.BodyAlgo)
	}
	var key [44]byte
	copy(key[:], ops.BodyKey)
	aes := new(Bencrypt.AES1)
	decBody, err := aes.DeAESGCM(key, encBody)
	if err != nil {
		p.setStage(STAGE_ERROR)
		return peerPub, myPub, nil, "", err
	}

	p.setStage(STAGE_COMPLETE)
	return peerPub, myPub, decBody, ops.Smsg, nil
}

// AFT Vault
type AVault struct {
	Path  string
	Limit int64
	// name rule: *, */, */*

	Algo    string // ecc1, rsa1
	Ext     string // webp, png, bin
	Public  []byte
	Private []byte

	TreeView map[string][]string // treeview with plain name
	PtoCtbl  map[string]string   // plain name -> cipher name
	CtoPtbl  map[string]string   // cipher name -> plain name
}

func (a *AVault) prehead() []byte {
	var ico Icons.Icons
	var v []byte
	switch a.Ext {
	case "webp":
		v, _ = ico.Zip_webp()
	case "png":
		v, _ = ico.Zip_png()
	default:
		return nil
	}
	v = append(v, make([]byte, 128-len(v)%128)...)
	return v
}

func (a *AVault) NewKeypair() error {
	var err error
	if a.Algo == "ecc1" {
		a.Public, a.Private, err = new(Bencrypt.ECC1).Genkey()
	} else if a.Algo == "rsa1" {
		a.Public, a.Private, err = new(Bencrypt.RSA1).Genkey(4096)
	} else {
		return errors.New("unsupported algorithm")
	}
	return err
}

// load vault from disk
func (a *AVault) Load(pw string, kf []byte) (string, error) {
	// 1. find account.*, name.* files
	files, err := os.ReadDir(a.Path)
	if err != nil {
		return "", err
	}
	found := 0
	accPath := ""
	nmPath := ""
	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), "account.") && !strings.HasSuffix(f.Name(), ".old") {
			found++
			accPath = filepath.Join(a.Path, f.Name())
		}
		if !f.IsDir() && strings.HasPrefix(f.Name(), "name.") && !strings.HasSuffix(f.Name(), ".old") {
			found++
			nmPath = filepath.Join(a.Path, f.Name())
		}
	}
	if found != 2 {
		return "", errors.New("cannot find data files")
	}

	// 2. Read account file
	accData, err := os.ReadFile(accPath)
	if err != nil {
		return "", err
	}
	var opsAcc Opsec.Opsec
	opsAcc.Reset()
	h, err := opsAcc.Read(bytes.NewReader(accData), 0)
	if err != nil {
		return "", err
	}
	opsAcc.View(h)
	if err := opsAcc.Decpw([]byte(pw), kf); err != nil {
		return opsAcc.Msg, err
	}

	// Load Smsg (Algo, Ext, Public, Private)
	parts := strings.Split(opsAcc.Smsg, "\n")
	if len(parts) != 4 {
		return opsAcc.Msg, errors.New("invalid account format")
	}
	a.Algo = parts[0]
	a.Ext = parts[1]
	b := new(Bencode.Bencode)
	b.Init()
	a.Public, err = b.Decode(parts[2])
	if err != nil {
		return opsAcc.Msg, err
	}
	a.Private, err = b.Decode(parts[3])
	if err != nil {
		return opsAcc.Msg, err
	}

	// 3. Read name file
	nameData, err := os.ReadFile(nmPath)
	if err != nil {
		return opsAcc.Msg, err
	}
	var opsName Opsec.Opsec
	opsName.Reset()
	rd := bytes.NewReader(nameData)
	h, err = opsName.Read(rd, 0)
	if err != nil {
		return opsAcc.Msg, err
	}
	opsName.View(h)
	if err := opsName.Decpub(a.Private, a.Public); err != nil {
		return opsAcc.Msg, err
	}

	// 4. Decrypt body
	var key [44]byte
	copy(key[:], opsName.BodyKey)
	aes := new(Bencrypt.AES1)
	encBody := make([]byte, opsName.Size)
	io.ReadFull(rd, encBody)
	decBody, err := aes.DeAESGCM(key, encBody)
	encBody = nil
	if err != nil {
		return opsAcc.Msg, err
	}

	// 5. Parse NameTable (\n delimiter)
	nameLines := strings.Split(string(decBody), "\n")
	decBody = nil
	a.PtoCtbl = make(map[string]string)
	a.CtoPtbl = make(map[string]string)
	for i := 0; i < len(nameLines)-1; i += 2 {
		if i+1 < len(nameLines) {
			a.PtoCtbl[nameLines[i]] = nameLines[i+1]
			a.CtoPtbl[nameLines[i+1]] = nameLines[i]
		}
	}

	// 6. make name tree
	a.TreeView = make(map[string][]string)
	a.TreeView[""] = make([]string, 0)
	for plain := range a.PtoCtbl {
		idx := strings.IndexAny(plain, "/")
		if idx == -1 { // golbal file
			a.TreeView[""] = append(a.TreeView[""], plain)
		} else { // folder or file in folder
			parent, child := plain[:idx+1], plain[idx+1:]
			if _, ok := a.TreeView[parent]; !ok { // add parent folder
				a.TreeView[parent] = make([]string, 0)
			}
			if child == "" { // add parent folder to root
				a.TreeView[""] = append(a.TreeView[""], parent)
			} else { // add child file
				a.TreeView[parent] = append(a.TreeView[parent], child)
			}
		}
	}
	for parent := range a.TreeView {
		sort.Strings(a.TreeView[parent])
	}
	a.Limit = 512 * 1024 * 1024
	return opsAcc.Msg, nil
}

// store name table to disk
func (a *AVault) StoreName() error {
	// make name list binary
	nameList := make([]string, 2*len(a.PtoCtbl))
	idx := 0
	for plain, cipher := range a.PtoCtbl {
		nameList[idx] = plain
		nameList[idx+1] = cipher
		idx += 2
	}
	data := []byte(strings.Join(nameList, "\n"))
	nameList = nil

	// make header
	var ops Opsec.Opsec
	ops.Reset()
	ops.Size = int64(len(data)) + 16
	header, err := ops.Encpub(a.Algo, a.Public, a.Private)
	if err != nil {
		return err
	}

	// encrypt body
	var key [44]byte
	copy(key[:], ops.BodyKey)
	aes := new(Bencrypt.AES1)
	encBody, err := aes.EnAESGCM(key, data)
	data = nil
	if err != nil {
		return err
	}

	// write to file
	path := filepath.Join(a.Path, "name."+a.Ext)
	os.Rename(path, path+".old")
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	prehead := a.prehead()
	if prehead != nil {
		file.Write(prehead)
	}
	if err := ops.Write(file, header); err != nil {
		return err
	}
	file.Write(encBody)
	return nil
}

// store account to disk
func (a *AVault) StoreAccount(pw string, kf []byte, msg string) error {
	// make account text
	b := new(Bencode.Bencode)
	b.Init()
	data := strings.Join([]string{a.Algo, a.Ext, b.Encode(a.Public, true), b.Encode(a.Private, true)}, "\n")

	// make header
	var ops Opsec.Opsec
	ops.Reset()
	ops.Msg = msg
	ops.Smsg = data
	algo := "arg1"
	if a.Algo == "rsa1" {
		algo = "pbk1"
	}
	header, err := ops.Encpw(algo, []byte(pw), kf)
	if err != nil {
		return err
	}

	// write to file
	path := filepath.Join(a.Path, "account."+a.Ext)
	os.Rename(path, path+".old")
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	prehead := a.prehead()
	if prehead != nil {
		file.Write(prehead)
	}
	return ops.Write(file, header)
}

// add file or folder to vault
func (a *AVault) Add(path string, dirname string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	// add file, assume dirname exists
	if !info.IsDir() {
		if info.Size() > a.Limit {
			return errors.New("file size too big")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return a.Write(dirname+info.Name(), data)
	}

	// add folder (single layer)
	if _, ok := a.PtoCtbl[info.Name()+"/"]; ok {
		return errors.New("folder already exists")
	}
	cParent := ""
	for {
		cParent = hex.EncodeToString(Bencrypt.Random(12)) + "/"
		if _, collision := a.CtoPtbl[cParent]; !collision {
			break
		}
	}
	os.Mkdir(filepath.Join(a.Path, cParent), 0755)
	a.PtoCtbl[info.Name()+"/"] = cParent
	a.CtoPtbl[cParent] = info.Name() + "/"
	a.TreeView[info.Name()+"/"] = make([]string, 0)
	a.TreeView[""] = append(a.TreeView[""], info.Name()+"/")
	sort.Strings(a.TreeView[""])

	files, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return a.StoreName() // store empty folder
	}
	for _, file := range files {
		if !file.IsDir() { // add only first layer
			if err := a.Add(filepath.Join(path, file.Name()), info.Name()+"/"); err != nil {
				return err
			}
		}
	}
	return nil
}

// delete file or folder from vault
func (a *AVault) Del(name string) error {
	isFolder := strings.HasSuffix(name, "/")

	// delete actual files, update tables
	for plain, cipher := range a.PtoCtbl {
		if plain == name || (isFolder && strings.HasPrefix(plain, name)) {
			os.RemoveAll(filepath.Join(a.Path, cipher))
			delete(a.CtoPtbl, cipher)
			delete(a.PtoCtbl, plain)
		}
	}

	// update treeview
	if isFolder {
		list := a.TreeView[""]
		for i, v := range list {
			if v == name {
				a.TreeView[""] = append(list[:i], list[i+1:]...)
				break
			}
		}
		delete(a.TreeView, name)

	} else {
		parent, child := "", name
		if idx := strings.Index(name, "/"); idx != -1 {
			parent, child = name[:idx+1], name[idx+1:]
		}
		list := a.TreeView[parent]
		for i, v := range list {
			if v == child {
				a.TreeView[parent] = append(list[:i], list[i+1:]...)
				break
			}
		}
	}
	return a.StoreName()
}

// rename file or folder in vault
func (a *AVault) Rename(src string, dst string) error {
	// check source
	if _, ok := a.PtoCtbl[src]; !ok {
		return errors.New("source not found")
	}
	if _, ok := a.PtoCtbl[dst]; ok {
		return errors.New("destination already exists")
	}
	isFolder := strings.HasSuffix(src, "/")
	if isFolder && !strings.HasSuffix(dst, "/") {
		return errors.New("invalid destination for folder")
	}
	idx0 := strings.Index(src, "/")
	idx1 := strings.Index(dst, "/")
	if !isFolder {
		dir0 := ""
		if idx0 != -1 {
			dir0 = src[:idx0+1]
		}
		dir1 := ""
		if idx1 != -1 {
			dir1 = dst[:idx1+1]
		}
		if dir0 != dir1 {
			return errors.New("invalid destination for file")
		}
	}

	// rename tables
	for pName, cName := range a.PtoCtbl {
		if pName == src || (isFolder && strings.HasPrefix(pName, src)) {
			updatedPName := dst + pName[len(src):]
			delete(a.PtoCtbl, pName)
			delete(a.CtoPtbl, cName)
			a.PtoCtbl[updatedPName] = cName
			a.CtoPtbl[cName] = updatedPName
		}
	}

	// update treeview
	if isFolder {
		idx := slices.Index(a.TreeView[""], src)
		if idx != -1 {
			a.TreeView[""][idx] = dst
			sort.Strings(a.TreeView[""])
		}
		a.TreeView[dst] = a.TreeView[src]
		delete(a.TreeView, src)

	} else {
		parent, oldChild := "", src
		if idx0 != -1 {
			parent, oldChild = src[:idx0+1], src[idx0+1:]
		}
		newChild := dst
		if idx1 != -1 {
			newChild = dst[idx1+1:]
		}
		idx := slices.Index(a.TreeView[parent], oldChild)
		if idx != -1 {
			a.TreeView[parent][idx] = newChild
			sort.Strings(a.TreeView[parent])
		}
	}
	return a.StoreName()
}

// read file from vault
func (a *AVault) Read(name string) ([]byte, error) {
	// find cipher name, read file
	cipher, ok := a.PtoCtbl[name]
	if !ok {
		return nil, errors.New("file not found in vault")
	}
	data, err := os.ReadFile(filepath.Join(a.Path, cipher))
	if err != nil {
		return nil, err
	}

	// read header
	var ops Opsec.Opsec
	ops.Reset()
	rd := bytes.NewReader(data)
	h, err := ops.Read(rd, 0)
	if err != nil {
		return nil, err
	}
	ops.View(h)
	if err := ops.Decpub(a.Private, a.Public); err != nil {
		return nil, err
	}

	// decrypt body
	var key [44]byte
	copy(key[:], ops.BodyKey)
	aes := new(Bencrypt.AES1)
	body := make([]byte, ops.Size)
	io.ReadFull(rd, body)
	return aes.DeAESGCM(key, body)
}

// write file to vault, make new if not exists
func (a *AVault) Write(name string, data []byte) error {
	// check size
	if int64(len(data)) > a.Limit {
		return errors.New("file size too big")
	}

	// check exists
	cipher, exists := a.PtoCtbl[name]
	if !exists {
		// split name
		parent, child := "", name
		if idx := strings.Index(name, "/"); idx != -1 {
			parent = name[:idx+1]
			child = name[idx+1:]
		}

		// make new cipher name, update tables
		for {
			cChild := hex.EncodeToString(Bencrypt.Random(12)) + "." + a.Ext
			if parent == "" {
				cipher = cChild
			} else {
				cipher = a.PtoCtbl[parent] + cChild
			}
			if _, collision := a.CtoPtbl[cipher]; !collision {
				break
			}
		}
		a.PtoCtbl[name] = cipher
		a.CtoPtbl[cipher] = name

		// update treeview
		if _, ok := a.TreeView[parent]; !ok {
			a.TreeView[parent] = make([]string, 0)
		}
		a.TreeView[parent] = append(a.TreeView[parent], child)
		sort.Strings(a.TreeView[parent])
	}

	// make header
	var ops Opsec.Opsec
	ops.Reset()
	ops.Size = int64(len(data)) + 16
	ops.BodyAlgo = "gcm1"
	header, err := ops.Encpub(a.Algo, a.Public, a.Private)
	if err != nil {
		return err
	}

	// encrypt body
	var key [44]byte
	copy(key[:], ops.BodyKey)
	aes := new(Bencrypt.AES1)
	encBody, err := aes.EnAESGCM(key, data)
	data = nil
	if err != nil {
		return err
	}

	// write file
	f, err := os.Create(filepath.Join(a.Path, cipher))
	if err != nil {
		return err
	}
	defer f.Close()
	if pre := a.prehead(); pre != nil {
		f.Write(pre)
	}
	if err := ops.Write(f, header); err != nil {
		return err
	}
	f.Write(encBody)
	return a.StoreName()
}

// sync vault with file system
func (a *AVault) Trim() (int, error) {
	count := 0

	// delete registered but not exists
	for plain, cipher := range a.PtoCtbl {
		fPath := filepath.Join(a.Path, cipher)
		if _, err := os.Stat(fPath); os.IsNotExist(err) {
			delete(a.PtoCtbl, plain)
			delete(a.CtoPtbl, cipher)
			count++
		}
	}

	// delete unregistered but exists
	err := filepath.Walk(a.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil || path == a.Path {
			return nil
		}
		rel, _ := filepath.Rel(a.Path, path)
		rel = filepath.ToSlash(rel)

		// skip account and name files
		if strings.HasPrefix(rel, "account.") || strings.HasPrefix(rel, "name.") {
			return nil
		}

		// make lookup key
		key := rel
		if info.IsDir() {
			key += "/"
		}

		// delete if not exists in table
		if _, ok := a.CtoPtbl[key]; !ok {
			os.RemoveAll(path)
			count++
			if info.IsDir() {
				return filepath.SkipDir
			}
		}
		return nil
	})
	if err != nil {
		return count, err
	}

	// rebuild treeview
	a.TreeView = make(map[string][]string)
	a.TreeView[""] = make([]string, 0)
	for plain := range a.PtoCtbl {
		idx := strings.Index(plain, "/")
		if idx == -1 { // global files
			a.TreeView[""] = append(a.TreeView[""], plain)
		} else { // folders and files in folders
			parent, child := plain[:idx+1], plain[idx+1:]
			if _, ok := a.TreeView[parent]; !ok { // add parent folder
				a.TreeView[parent] = make([]string, 0)
			}
			if child == "" { // add parent folder to root
				a.TreeView[""] = append(a.TreeView[""], parent)
			} else { // add child file
				a.TreeView[parent] = append(a.TreeView[parent], child)
			}
		}
	}

	// sort and save
	for k := range a.TreeView {
		sort.Strings(a.TreeView[k])
	}
	return count, a.StoreName()
}
