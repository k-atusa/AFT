// test798b : project USAG AFT-desktop cli
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/k-atusa/USAG-Lib/Opsec"
)

// command line parser
type Config struct {
	Mode     string
	Target   string
	Output   string
	PW       string
	KF       []byte
	Msg      string
	IsLegacy bool
}

func (cfg *Config) Init() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError) // empty string means auto
	fs.StringVar(&cfg.Mode, "m", "help", "work mode: import, export, view, trim, version, help")
	fs.StringVar(&cfg.Output, "o", "", "output folder")
	fs.StringVar(&cfg.PW, "pw", "", "password")
	fs.StringVar(&cfg.Msg, "msg", "", "message")
	fs.BoolVar(&cfg.IsLegacy, "legacy", false, "use legacy mode (rsa1, png)")

	// get keyfile
	kfpath := ""
	fs.StringVar(&kfpath, "kf", "", "key file path")

	// parse and get target folder
	fs.Parse(os.Args[1:])
	cfg.Target = fs.Arg(0)

	if kfpath == "" {
		cfg.KF = nil
	} else if _, err := os.Stat(kfpath); err == nil { // file
		fmt.Println("reading keyfile")
		cfg.KF, err = os.ReadFile(kfpath)
		if err != nil {
			fmt.Println(err)
			cfg.KF = nil
		}
	}
	if len(cfg.KF) > 1024 {
		fmt.Println("keyfile is truncated to 1024B")
		cfg.KF = cfg.KF[:1024]
	}
}

// main functions
func f_import() error {
	// check arguments
	if Cfg.Target == "" || Cfg.Output == "" {
		return errors.New("target and output are required for import")
	}
	if err := os.MkdirAll(Cfg.Output, 0755); err != nil {
		return err
	}
	info, err := os.Stat(Cfg.Output)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("output is not a directory")
	}

	// make AVault
	v := &AVault{Path: Cfg.Output, Limit: 512 * 1048576, TreeView: make(map[string][]string), PtoCtbl: make(map[string]string), CtoPtbl: make(map[string]string)}
	if Cfg.IsLegacy {
		v.Algo = "rsa1"
		v.Ext = "png"
	} else {
		v.Algo = "ecc1"
		v.Ext = "webp"
	}
	if err := v.NewKeypair(); err != nil {
		return err
	}
	if err := v.StoreAccount(Cfg.PW, Cfg.KF, Cfg.Msg); err != nil {
		return err
	}

	// search target folder
	entries, err := os.ReadDir(Cfg.Target)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		fullPath := filepath.Join(Cfg.Target, entry.Name())
		fmt.Printf("Adding: %s\n", fullPath)
		err = v.Add(fullPath, "")
		if err != nil {
			return err
		}
	}

	fmt.Printf("\nSuccessfully imported vault at: %s\n", v.Path)
	return nil
}

func f_export() error {
	// check arguments
	if Cfg.Target == "" || Cfg.Output == "" {
		return errors.New("target and output are required for export")
	}
	if err := os.MkdirAll(Cfg.Output, 0755); err != nil {
		return err
	}

	// load vault
	v := &AVault{Path: Cfg.Target}
	msg, err := v.Load(Cfg.PW, Cfg.KF)
	if msg != "" {
		fmt.Printf("[msg] %s\n", msg)
	}
	if err != nil {
		return err
	}
	fmt.Println("Vault unlocked")

	// restore files
	for plainName := range v.PtoCtbl {
		// folder: make directory
		if strings.HasSuffix(plainName, "/") {
			dirPath := filepath.Join(Cfg.Output, plainName)
			if err := os.MkdirAll(dirPath, 0755); err != nil {
				return err
			}
			fmt.Printf("Created directory: %s\n", plainName)
			continue
		}

		// file: read data
		data, err := v.Read(plainName)
		if err != nil {
			fmt.Printf("Failed to read %s: %v\n", plainName, err)
			continue
		}

		// write file
		targetFilePath := filepath.Join(Cfg.Output, plainName)
		if err := os.MkdirAll(filepath.Dir(targetFilePath), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(targetFilePath, data, 0644); err != nil {
			return err
		}
		fmt.Printf("Exported file: %s\n", plainName)
	}

	fmt.Printf("\nSuccessfully exported to: %s\n", Cfg.Output)
	return nil
}

func f_view() error {
	// check arguments, load vault
	if Cfg.Target == "" {
		return errors.New("target is required for view")
	}
	v := &AVault{Path: Cfg.Target}
	msg, err := v.Load(Cfg.PW, Cfg.KF)
	if err != nil {
		fmt.Printf("[msg] %s\n", msg)
		return err
	}

	// print vault metadata
	fmt.Println("========== AFT Vault Metadata ==========")
	fmt.Printf("Message     : %s\n", msg)
	fmt.Printf("Algorithm   : %s\n", v.Algo)
	fmt.Printf("File Format : %s\n", v.Ext)
	fmt.Printf("Total Items : %d\n", len(v.PtoCtbl))
	fmt.Printf("Public Key  : %s (%d B)\n", hex.EncodeToString(Opsec.Crc32(v.Public)), len(v.Public))
	fmt.Printf("Private Key : %s (%d B)\n", hex.EncodeToString(Opsec.Crc32(v.Private)), len(v.Private))

	// print file list
	fmt.Println("\n========== Files List ==========")
	if len(v.TreeView[""]) == 0 {
		fmt.Println("(No items found in vault)")
	}
	for _, name := range v.TreeView[""] {
		if strings.HasSuffix(name, "/") {
			fmt.Println(name)
			children := v.TreeView[name]
			for _, child := range children {
				fmt.Printf("    %s\n", child)
			}
		} else {
			fmt.Println(name)
		}
	}
	return nil
}

func f_trim() error {
	if Cfg.Target == "" {
		return errors.New("target is required for trim")
	}
	v := &AVault{Path: Cfg.Target}
	msg, err := v.Load(Cfg.PW, Cfg.KF)
	if err != nil {
		return err
	}

	// trim vault
	fmt.Println("Triming vault...")
	count, err := v.Trim()
	fmt.Printf("Sync completed: %d items cleaned.\n", count)
	if err != nil {
		return err
	}

	// make new key pair
	oldPub, oldPriv := v.Public, v.Private
	fmt.Println("Regenerating new key pair...")
	err = v.NewKeypair()
	if err != nil {
		return err
	}
	newPub, newPriv := v.Public, v.Private

	// re-encrypt all files
	for plain := range v.PtoCtbl {
		if strings.HasSuffix(plain, "/") {
			continue
		}
		fmt.Printf("Re-encrypting: %s\n", plain)

		v.Public, v.Private = oldPub, oldPriv
		data, err := v.Read(plain)
		if err != nil {
			fmt.Printf("    Skip: Decryption failed\n")
			continue
		}

		v.Public, v.Private = newPub, newPriv
		v.Write(plain, data)
	}

	// save account and name
	fmt.Println("Saving account and name...")
	v.Public, v.Private = newPub, newPriv
	err = v.StoreAccount(Cfg.PW, Cfg.KF, msg)
	if err != nil {
		return err
	}
	return v.StoreName()
}

var Cfg Config

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[PANIC] %v", err)
		}
	}()
	var err error
	Cfg.Init()
	fmt.Println("Configuration completed")
	switch Cfg.Mode {
	case "import":
		err = f_import()
	case "export":
		err = f_export()
	case "view":
		err = f_view()
	case "trim":
		err = f_trim()
	case "version":
		fmt.Println("2026 @k-atusa [USAG] AFT-lite v0.1") // version indicator
	default: // help
		fmt.Println("-m mode [import|export|view|trim|version|help] -o outdir -pw password -kf keyfile -msg message")
		fmt.Println("import: target -> outdir +(pw, kf, msg)")
		fmt.Println("export: target -> outdir +(pw, kf)")
		fmt.Println("view: list all files +(pw, kf)")
		fmt.Println("trim: trim and rebuild +(pw, kf)")
	}
	if err != nil {
		fmt.Printf("\n[ERROR] %v\n", err)
	}
}
