// test798a : project USAG AFT-desktop core
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/k-atusa/USAG-Lib/Bencrypt"
	"github.com/k-atusa/USAG-Lib/Icons"
	"github.com/k-atusa/USAG-Lib/Opsec"
)

var AFT_VERSION string = "2026 @k-atusa [USAG] AFT v1.0.0"

// AFT Vault
type AVault struct {
	Path  string
	limit int64

	AlgoType string // pbk1, arg1
	Ext      string // webp, png, bin
	VaultKey string

	// name rule: *, */, */*
	TreeView map[string][]string // treeview with plain name
	PtoCtbl  map[string]string   // plain name -> cipher name
	CtoPtbl  map[string]string   // cipher name -> plain name
}

func (a *AVault) prehead() []byte {
	var ico []byte
	switch a.Ext {
	case "webp":
		ico = Icons.ZipWebp
	case "png":
		ico = Icons.ZipPng
	default:
		return nil
	}
	return append(ico, make([]byte, 128-len(ico)%128)...)
}

func (a *AVault) qread(path string, pw string, kf []byte) (data []byte, msg string, smsg string, err error) {
	// open file
	f, err := os.Open(path)
	if err != nil {
		return data, msg, smsg, err
	}
	defer f.Close()

	// read and decrypt header
	ops := new(Opsec.Opsec)
	ops.Reset()
	h, err := ops.Read(f, 0)
	if err != nil {
		return data, msg, smsg, err
	}
	ops.View(h)
	msg = ops.Msg
	err = ops.Decpw([]byte(pw), kf)
	smsg = ops.Smsg
	if err != nil {
		return data, msg, smsg, err
	}
	if ops.Size <= 0 { // only header, no body
		return data, msg, smsg, nil
	}

	// decrypt body
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init(ops.BodyAlgo, ops.BodyKey); err != nil {
		return data, msg, smsg, err
	}
	buf := new(bytes.Buffer)
	if err := sm.DeFile(f, ops.Size, buf); err != nil {
		return data, msg, smsg, err
	}
	data = buf.Bytes()
	return data, msg, smsg, nil
}

func (a *AVault) hwrite(msg string, smsg string, path string, pw string, kf []byte) error {
	// encrypt header
	ops := new(Opsec.Opsec)
	ops.Reset()
	ops.Msg = msg
	ops.Smsg = smsg
	header, err := ops.Encpw(a.AlgoType, []byte(pw), kf)
	if err != nil {
		return err
	}

	// write header to file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	f.Write(a.prehead())
	return ops.Write(f, header)
}

func (a *AVault) qwrite(data []byte, path string, pw string) error {
	// prepare worker
	sm := new(Bencrypt.SymMaster)
	if err := sm.Init("gcm1", make([]byte, 44)); err != nil {
		return err
	}

	// encrypt header
	ops := new(Opsec.Opsec)
	ops.Reset()
	ops.Size = sm.AfterSize(int64(len(data)))
	ops.BodyAlgo = "gcm1"
	header, err := ops.Encpw(a.AlgoType, []byte(pw), nil)
	if err == nil {
		err = sm.Init(sm.Algo, ops.BodyKey)
	}
	if err != nil {
		return err
	}

	// write header and body to file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	f.Write(a.prehead())
	if err := ops.Write(f, header); err != nil {
		return err
	}
	return sm.EnFile(bytes.NewBuffer(data), int64(len(data)), f)
}

// load vault from disk
func (a *AVault) Load(pw string, kf []byte) (string, error) {
	// 1. find account.*, name.* files
	files, err := os.ReadDir(a.Path)
	if err != nil {
		return "", err
	}
	accPath, nmPath := "", ""
	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), "account.") && !strings.HasSuffix(f.Name(), ".old") {
			accPath = filepath.Join(a.Path, f.Name())
		}
		if !f.IsDir() && strings.HasPrefix(f.Name(), "name.") && !strings.HasSuffix(f.Name(), ".old") {
			nmPath = filepath.Join(a.Path, f.Name())
		}
	}
	if accPath == "" || nmPath == "" {
		return "", errors.New("cannot find data files")
	}

	// 2. load account file, set (AlgoType, Ext, VaultKey)
	_, msg, smsg, err := a.qread(accPath, pw, kf)
	if err != nil {
		return msg, err
	}
	parts := strings.Split(smsg, "\n")
	if len(parts) != 3 {
		return msg, errors.New("invalid account file")
	}
	a.AlgoType, a.Ext, a.VaultKey = parts[0], parts[1], parts[2]

	// 3. load name file
	data, _, _, err := a.qread(nmPath, a.VaultKey, nil)
	if err != nil {
		return msg, err
	}
	nmLines := strings.Split(string(data), "\n")
	data = nil
	a.PtoCtbl = make(map[string]string)
	a.CtoPtbl = make(map[string]string)
	for i := 0; i < len(nmLines)-1; i += 2 {
		if i+1 < len(nmLines) {
			a.PtoCtbl[nmLines[i]] = nmLines[i+1]
			a.CtoPtbl[nmLines[i+1]] = nmLines[i]
		}
	}

	// 4. make name tree
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
	a.limit = 512 * 1048576
	return msg, nil
}

// store name table to disk
func (a *AVault) StoreName() error {
	// 1. make name list binary
	nameList := make([]string, 2*len(a.PtoCtbl))
	idx := 0
	for plain, cipher := range a.PtoCtbl {
		nameList[idx] = plain
		nameList[idx+1] = cipher
		idx += 2
	}
	data := []byte(strings.Join(nameList, "\n"))
	nameList = nil

	// 2. write
	path := filepath.Join(a.Path, "name."+a.Ext)
	os.Rename(path, path+".old")
	return a.qwrite(data, path, a.VaultKey)
}

// store account to disk, !!! VaultKey is not changed !!!
func (a *AVault) StoreAccount(pw string, kf []byte, msg string) error {
	path := filepath.Join(a.Path, "account."+a.Ext)
	os.Rename(path, path+".old")
	return a.hwrite(msg, a.AlgoType+"\n"+a.Ext+"\n"+a.VaultKey, path, pw, kf)
}

// add file or folder to vault
func (a *AVault) Add(path string, dirname string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	// add file, assume dirname exists
	if !info.IsDir() {
		if info.Size() > a.limit {
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
	path := filepath.Join(a.Path, cipher)
	data, _, _, err := a.qread(path, a.VaultKey, nil)
	return data, err
}

// write file to vault, make new if not exists
func (a *AVault) Write(name string, data []byte) error {
	// check size
	if int64(len(data)) > a.limit {
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

	// update file
	path := filepath.Join(a.Path, cipher)
	if err := a.qwrite(data, path, a.VaultKey); err != nil {
		return err
	}
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
