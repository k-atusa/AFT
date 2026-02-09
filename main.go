// test798c : project USAG AFT-desktop gui
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	_ "golang.org/x/image/webp"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/k-atusa/USAG-Lib/Opsec"
)

// ===== theme =====
type U1Theme struct{}

func (m U1Theme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	if name == theme.ColorNameForeground { // change only foreground color
		if variant == theme.VariantDark {
			return color.White
		}
		return color.Black
	}
	return theme.DefaultTheme().Color(name, variant)
}

func (m U1Theme) Font(s fyne.TextStyle) fyne.Resource     { return theme.DefaultTheme().Font(s) }
func (m U1Theme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (m U1Theme) Size(n fyne.ThemeSizeName) float32       { return theme.DefaultTheme().Size(n) }

// ===== config =====
type U1Config struct {
	AutoExpire int      `json:"autoexpire"`
	Shortcuts  []string `json:"shortcuts"`
}

func (c *U1Config) GetPath() (string, error) {
	// find actual program path
	exePath, err := os.Executable()
	if err != nil {
		return "./config.json", err
	}
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		realPath = exePath
	}
	return filepath.Join(filepath.Dir(realPath), "config.json"), nil
}

func (c *U1Config) Load() error {
	path, err := c.GetPath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.Shortcuts = []string{}
			c.AutoExpire = 20
			return c.Store()
		}
		return err
	}
	return json.Unmarshal(data, c)
}

func (c *U1Config) Store() error {
	path, err := c.GetPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// ===== login =====
type LoginPage struct {
	App    fyne.App
	Window fyne.Window

	Config *U1Config
	Vault  *AVault

	VaultPath string
	KeyFile   []byte
	Password  string
	NewPath   string
	ImgType   string
	KeyAlgo   string
}

func (l *LoginPage) Main(c *U1Config, v *AVault) {
	l.Config = c
	l.Vault = v
	err := l.Config.Load()

	l.App = app.New()
	l.App.Settings().SetTheme(&U1Theme{})
	l.Window = l.App.NewWindow("AFT Vault - Login")
	l.Fill()
	l.Window.Resize(fyne.NewSize(720, 480))
	l.Window.CenterOnScreen()
	if err != nil {
		dialog.ShowError(fmt.Errorf("Config Load Fail: %s", err), l.Window)
	}
	l.Window.ShowAndRun()
}

func (l *LoginPage) Fill() {
	// group0: vault path selection
	lbl0a := widget.NewLabelWithStyle("Path not selected", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	lbl0b := widget.NewLabel("Msg:")
	sel0 := widget.NewSelect(l.Config.Shortcuts, func(s string) {
		l.VaultPath = s
		l.Vault.Path = s
		lbl0a.SetText(s)
		msg, _ := l.Vault.Load("", nil)
		lbl0b.SetText("Msg: " + msg)
	})
	sel0.PlaceHolder = "Select Shortcut"
	btn0 := widget.NewButtonWithIcon("Select Manually", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(list fyne.ListableURI, err error) {
			if err == nil && list != nil {
				l.VaultPath = list.Path()
				l.Vault.Path = list.Path()
				lbl0a.SetText(list.Path())
				msg, _ := l.Vault.Load("", nil)
				lbl0b.SetText("Msg: " + msg)
			}
		}, l.Window)
	})

	// group1: keyfile selection
	lbl1 := widget.NewLabel("[0B 00000000] keyfile not selected")
	btn1a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() {
		dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
			if err == nil && r != nil {
				// 1. Read file (max 1024 bytes)
				file, err := os.Open(r.URI().Path())
				if err != nil {
					dialog.ShowError(err, l.Window)
					return
				}
				defer file.Close()
				buf := make([]byte, 1024)
				n, _ := io.ReadFull(file, buf)
				data := buf[:n]

				// 2. Set Data & Update UI
				l.KeyFile = data
				crc := hex.EncodeToString(Opsec.Crc32(data))
				lbl1.SetText(fmt.Sprintf("[%dB, %s] %s", n, crc, filepath.Base(r.URI().Path())))
			} else {
				l.KeyFile = nil
				lbl1.SetText("[0B 00000000] keyfile not selected")
			}
		}, l.Window)
	})
	ent1 := widget.NewEntry()
	ent1.SetPlaceHolder("port: 8001")
	btn1b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() {
		// 1. Get IP Address
		ips, err := GetIPs(true)
		if err != nil {
			dialog.ShowError(err, l.Window)
			return
		}
		port := "8001"
		if ent1.Text != "" {
			port = ent1.Text
		}
		for i, r := range ips {
			ips[i] = r + ":" + port
		}
		dialog.ShowInformation("IP Address", strings.Join(ips, "\n"), l.Window)

		// 2. Receive KeyFile
		go func() {
			listener, err := net.Listen("tcp", ":"+port)
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, l.Window) })
				return
			}
			defer listener.Close()
			listener.(*net.TCPListener).SetDeadline(time.Now().Add(90 * time.Second)) // 90s timeout
			conn, err := listener.Accept()
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, l.Window) })
				return
			}
			defer conn.Close()

			p := new(TPprotocol)
			p.Init(0, conn)
			fromPub, toPub, data, _, err := p.ReceiveData()
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, l.Window) })
				return
			}

			// 3. Update UI
			fyne.Do(func() {
				l.KeyFile = data
				crc0 := hex.EncodeToString(Opsec.Crc32(data))
				crc1 := hex.EncodeToString(Opsec.Crc32(fromPub))
				crc2 := hex.EncodeToString(Opsec.Crc32(toPub))
				lbl1.SetText(fmt.Sprintf("[%dB, %s] from %s to %s", len(data), crc0, crc1, crc2))
			})
		}()
	})
	box1 := container.NewBorder(nil, nil, container.NewHBox(btn1a, btn1b), nil, ent1)

	// group2: password and login
	ent2 := widget.NewPasswordEntry()
	ent2.SetPlaceHolder("Password")
	btn2 := widget.NewButtonWithIcon("Login", theme.LoginIcon(), func() {
		l.Password = ent2.Text
		l.Vault.Path = l.VaultPath
		if l.VaultPath == "" {
			dialog.ShowError(fmt.Errorf("Vault path not selected"), l.Window)
			return
		}
		_, err := l.Vault.Load(l.Password, l.KeyFile)
		if err != nil {
			dialog.ShowError(err, l.Window)
			return
		}
		l.Password = ""
		l.KeyFile = nil
		l.switchToViewer()
	})
	btn2.Importance = widget.HighImportance

	// guoup3: left box
	box3 := container.NewVBox(
		lbl0a, lbl0b, sel0, btn0,
		widget.NewSeparator(),
		lbl1, box1,
		layout.NewSpacer(),
		ent2, btn2,
	)

	// group4: new vault path selection
	lbl4 := widget.NewLabelWithStyle("Path not selected", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	btn4 := widget.NewButtonWithIcon("Select", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(list fyne.ListableURI, err error) {
			if err == nil && list != nil {
				l.NewPath = list.Path()
				lbl4.SetText(list.Path())
			}
		}, l.Window)
	})

	// group5: vault config
	sel5a := widget.NewSelect([]string{"webp", "png", "bin"}, func(s string) { l.ImgType = s })
	sel5a.SetSelected("webp")
	l.ImgType = "webp"
	sel5b := widget.NewSelect([]string{"ecc1", "rsa1"}, func(s string) { l.KeyAlgo = s })
	sel5b.SetSelected("ecc1")
	l.KeyAlgo = "ecc1"

	// group6: generate new vault
	ent6 := widget.NewEntry()
	ent6.SetPlaceHolder("Vault Public Message")
	btn6 := widget.NewButtonWithIcon("Generate", theme.ContentAddIcon(), func() {
		// 1. check target path, get params
		if l.NewPath == "" {
			dialog.ShowError(fmt.Errorf("Target path not selected"), l.Window)
			return
		}
		pw := ent2.Text
		kf := l.KeyFile
		msg := ent6.Text

		// 2. set config
		v := &AVault{Path: l.NewPath,
			Limit:    512 * 1048576,
			Algo:     l.KeyAlgo,
			Ext:      l.ImgType,
			TreeView: make(map[string][]string),
			PtoCtbl:  make(map[string]string),
			CtoPtbl:  make(map[string]string)}

		// 3. generate vault
		err := v.NewKeypair()
		if err != nil {
			dialog.ShowError(err, l.Window)
			return
		}
		if err := v.StoreAccount(pw, kf, msg); err != nil {
			dialog.ShowError(err, l.Window)
			return
		}
		if err := v.Write("welcome.txt", []byte("Welcome to your vault!\n볼트 로그인을 환영합니다!")); err != nil {
			dialog.ShowError(err, l.Window)
			return
		}
		dialog.ShowInformation("Success", "Vault generated successfully", l.Window)
	})
	btn6.Importance = widget.HighImportance

	// group7: right box
	rightBox := container.NewVBox(
		container.NewBorder(nil, nil, nil, btn4, lbl4),
		widget.NewSeparator(),
		widget.NewLabel("Password and KeyFile are loaded from left card"),
		container.NewBorder(nil, nil, widget.NewLabel("Image Format"), sel5a),
		container.NewBorder(nil, nil, widget.NewLabel("Encryption Algorithm"), sel5b),
		layout.NewSpacer(),
		ent6, btn6,
	)

	// group8: main grid
	box8 := container.NewGridWithColumns(2,
		widget.NewCard("Unlock Existing", "기존 저장소 로그인", box3),
		widget.NewCard("Create New", "새로운 저장소 생성", rightBox),
	)
	l.Window.SetContent(container.NewPadded(box8))
}

func (l *LoginPage) switchToViewer() {
	v := new(ViewPage)
	v.App = l.App
	v.Main(l.Config, l.Vault)
	l.Window.Close()
}

// ===== viewer =====
type ViewPage struct {
	App    fyne.App
	Window fyne.Window

	ContentArea *fyne.Container
	Tree        *widget.Tree
	LogoutTimer *time.Timer
	LogoutTime  time.Time
	LblTimer    *widget.Label
	LblSelected *widget.Label

	Vault        *AVault
	AutoExpire   bool
	ExpireMinute int
	CurPath      string
}

func (v *ViewPage) Main(c *U1Config, av *AVault) {
	v.Vault = av
	if c.AutoExpire > 0 {
		v.AutoExpire = true
		v.ExpireMinute = c.AutoExpire
	} else {
		v.AutoExpire = false
	}
	v.Window = v.App.NewWindow("AFT Vault - Viewer")
	v.Fill()
	v.Window.Resize(fyne.NewSize(800, 480))
	v.Window.CenterOnScreen()
	v.Window.Show()
}

func (v *ViewPage) Fill() {
	// group0: top toolbar
	box0 := container.NewHBox(
		widget.NewButtonWithIcon("Import", theme.FileIcon(), v.ImportFile),
		widget.NewButtonWithIcon("Import", theme.FolderIcon(), v.ImportFolder),
		widget.NewButtonWithIcon("Export", theme.FolderOpenIcon(), v.Export),
		widget.NewSeparator(),
		widget.NewButtonWithIcon("Rename", theme.DocumentCreateIcon(), v.Rename),
		widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), v.Delete),
		widget.NewSeparator(),
		widget.NewButtonWithIcon("Send", theme.UploadIcon(), func() { v.transfer(true) }),
		widget.NewButtonWithIcon("Share", theme.MailSendIcon(), func() { v.transfer(false) }),
		layout.NewSpacer(),
		widget.NewButtonWithIcon("Reset PW", theme.AccountIcon(), v.ResetPW),
	)

	// group1: left tree
	v.Tree = widget.NewTree(
		func(id string) []string {
			names := v.Vault.TreeView[id]
			paths := make([]string, len(names))
			for i, name := range names {
				paths[i] = id + name
			}
			return paths
		},
		func(id string) bool {
			_, ok := v.Vault.TreeView[id]
			return ok
		},
		func(branch bool) fyne.CanvasObject {
			if branch {
				return widget.NewLabelWithStyle("Dir", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			}
			return widget.NewLabel("File")
		},
		func(id string, branch bool, obj fyne.CanvasObject) {
			l := obj.(*widget.Label)
			if branch {
				l.SetText(id)
			} else {
				idx := strings.LastIndex(id, "/")
				if idx == -1 {
					l.SetText(id)
				} else {
					l.SetText(id[idx+1:])
				}
			}
		},
	)
	v.Tree.OnSelected = v.selected

	// group2: right content area
	v.ContentArea = container.NewStack(widget.NewLabelWithStyle("Select a file to view", fyne.TextAlignCenter, fyne.TextStyle{Italic: true}))
	scroll2 := container.NewScroll(v.ContentArea)

	// group3: bottom bar
	lbl3 := widget.NewLabel(fmt.Sprintf("%s | %s | %s", v.Vault.Algo, v.Vault.Ext, v.Vault.Path))
	v.LblSelected = widget.NewLabel("2026 @k-atusa [USAG] AFT v0.2") // version indicator
	var box3a []fyne.CanvasObject = []fyne.CanvasObject{lbl3, v.LblSelected, layout.NewSpacer()}

	// group4: bottom right bar
	if v.AutoExpire {
		v.LblTimer = widget.NewLabel("Expire in 00:00")
		btnExtend := widget.NewButton("Extend", func() { v.ResetTimer() })
		btnExtend.Importance = widget.HighImportance
		box3a = append(box3a, v.LblTimer, btnExtend)
	}
	btn3 := widget.NewButtonWithIcon("Logout", theme.LogoutIcon(), func() {
		dialog.ShowConfirm("Logout", "Logout Now?", func(b bool) {
			if b {
				v.Vault = nil
				v.Window.Close()
			}
		}, v.Window)
	})
	btn3.Importance = widget.DangerImportance
	box3a = append(box3a, btn3)
	box3b := container.NewHBox(box3a...)

	// group5: main layout
	split := container.NewHSplit(v.Tree, scroll2)
	split.Offset = 0.3
	box5 := container.NewBorder(box0, box3b, nil, nil, split)
	v.Window.SetContent(box5)

	// Start Timer
	if v.AutoExpire {
		v.ResetTimer()
		go v.UpdateTimerLoop()
	}
}

func (v *ViewPage) ResetTimer() {
	if !v.AutoExpire {
		return
	}
	if v.LogoutTimer != nil {
		v.LogoutTimer.Stop()
	}
	v.LogoutTime = time.Now().Add(time.Duration(v.ExpireMinute) * time.Minute)
	v.LogoutTimer = time.AfterFunc(time.Duration(v.ExpireMinute)*time.Minute, func() {
		fyne.Do(func() {
			v.Vault = nil
			v.Window.Close()
		})
	})
}

func (v *ViewPage) UpdateTimerLoop() {
	if !v.AutoExpire {
		return
	}
	for {
		time.Sleep(1 * time.Second)
		remaining := time.Until(v.LogoutTime)
		if remaining <= 0 {
			break
		}
		if v.LblTimer != nil {
			fyne.Do(func() {
				v.LblTimer.SetText(fmt.Sprintf("Expire in %02d:%02d", int(remaining.Minutes()), int(remaining.Seconds())%60))
			})
		}
	}
}

// inner helper functions
func (v *ViewPage) selected(path string) {
	v.LblSelected.SetText(path)
	v.CurPath = path
	v.ContentArea.Objects = nil // Clear current content
	defer v.ContentArea.Refresh()

	// 1. Check if Folder
	if strings.HasSuffix(path, "/") {
		v.ContentArea.Objects = []fyne.CanvasObject{widget.NewLabel("Folder: " + path)}
		return
	}

	// 2. Check File Size (via Cipher Path)
	cipherName, ok := v.Vault.PtoCtbl[path]
	if !ok {
		v.ContentArea.Objects = []fyne.CanvasObject{widget.NewLabel("File not found in name table")}
		return
	}
	info, err := os.Stat(filepath.Join(v.Vault.Path, cipherName))
	if err != nil {
		v.ContentArea.Objects = []fyne.CanvasObject{widget.NewLabel("Error stating file: " + err.Error())}
		return
	}
	ext := strings.ToLower(filepath.Ext(path))
	isImg := (ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".webp" || ext == ".gif")
	if !isImg && info.Size() > 4*1048576 {
		v.ContentArea.Objects = []fyne.CanvasObject{widget.NewLabel("Large File (4MB+)")}
		return
	}

	// 3. Read and Display
	data, err := v.Vault.Read(path)
	if err != nil {
		v.ContentArea.Objects = []fyne.CanvasObject{widget.NewLabel("Error reading file: " + err.Error())}
		return
	}

	if isImg {
		img := canvas.NewImageFromResource(fyne.NewStaticResource(filepath.Base(path), data))
		img.FillMode = canvas.ImageFillContain
		v.ContentArea.Objects = []fyne.CanvasObject{img}
	} else {
		entry := widget.NewMultiLineEntry()
		entry.TextStyle = fyne.TextStyle{Monospace: true}
		entry.SetText(string(data))

		btnSave := widget.NewButtonWithIcon("Save Changes", theme.DocumentSaveIcon(), func() {
			if err := v.Vault.Write(path, []byte(entry.Text)); err != nil {
				dialog.ShowError(err, v.Window)
			} else {
				dialog.ShowInformation("Success", "File saved successfully", v.Window)
			}
		})

		content := container.NewBorder(nil, btnSave, nil, nil, entry)
		v.ContentArea.Objects = []fyne.CanvasObject{content}
	}
}

func (v *ViewPage) transfer(cut bool) {
	if v.CurPath == "" || strings.HasSuffix(v.CurPath, "/") {
		return
	}
	entry := widget.NewEntry()
	entry.SetPlaceHolder("IP:port 127.0.0.1:8001")
	dialog.ShowCustomConfirm("Transfer", "Send", "Cancel", entry, func(b bool) {
		// 1. Get IP Address
		if !b {
			return
		}
		addr := "127.0.0.1"
		if entry.Text != "" {
			addr = entry.Text
		}
		if !strings.Contains(addr, ":") {
			addr += ":8001"
		}

		// 2. Read Data
		data, err := v.Vault.Read(v.CurPath)
		if err != nil {
			dialog.ShowError(err, v.Window)
			return
		}
		if cut && len(data) > 1024 {
			data = data[:1024]
		}

		go func() {
			// 3. Connect to receiver
			var conn net.Conn
			var err error
			for range 5 { // 5 attempts
				conn, err = net.DialTimeout("tcp", addr, 10*time.Second)
				if err == nil {
					break
				}
				time.Sleep(3 * time.Second)
			}
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, v.Window) })
				return
			}
			defer conn.Close()

			// 4. Initialize Protocol
			var mode uint16 = 0
			if v.Vault.Algo == "rsa1" {
				mode |= MODE_LEGACY
				mode |= MODE_RSA_4K
			}
			p := new(TPprotocol)
			p.Init(uint16(mode), conn)

			// 5. Send Data
			fromPub, toPub, err := p.SendData(data, "")
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, v.Window) })
				return
			}
			crc0 := hex.EncodeToString(Opsec.Crc32(data))
			crc1 := hex.EncodeToString(Opsec.Crc32(fromPub))
			crc2 := hex.EncodeToString(Opsec.Crc32(toPub))
			fyne.Do(func() {
				dialog.ShowInformation("Transfer", fmt.Sprintf("[%dB, %s] from %s to %s", len(data), crc0, crc1, crc2), v.Window)
			})
		}()
	}, v.Window)
}

// Worker Functions
func (v *ViewPage) ImportFile() {
	dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err == nil && reader != nil {
			data, err := io.ReadAll(reader)
			if err != nil {
				dialog.ShowError(err, v.Window)
				return
			}
			defer reader.Close()

			// Determine target directory
			targetDir := ""
			if v.CurPath != "" {
				if _, isDir := v.Vault.TreeView[v.CurPath]; isDir {
					targetDir = v.CurPath
				} else {
					if idx := strings.LastIndex(strings.TrimSuffix(v.CurPath, "/"), "/"); idx != -1 {
						targetDir = v.CurPath[:idx+1]
					}
				}
			}

			fname := reader.URI().Name()
			if err := v.Vault.Write(targetDir+fname, data); err != nil {
				dialog.ShowError(err, v.Window)
				return
			}
			v.Tree.Refresh()
		}
	}, v.Window)
}

func (v *ViewPage) ImportFolder() {
	dialog.ShowFolderOpen(func(list fyne.ListableURI, err error) {
		if err == nil && list != nil {
			if err := v.Vault.Add(list.Path(), ""); err != nil { // save to global space
				dialog.ShowError(err, v.Window)
				return
			}
			v.Tree.Refresh()
		}
	}, v.Window)
}

func (v *ViewPage) Export() {
	targetName := v.CurPath
	if targetName == "" {
		targetName = "Entire Vault"
	}

	dialog.ShowConfirm("Export", "Export "+targetName+" to current directory?", func(b bool) {
		if !b {
			return
		}
		destRootDir, _ := os.Getwd() // Use current working directory
		count := 0

		if v.CurPath != "" && !strings.HasSuffix(v.CurPath, "/") { // CASE 1: Single File
			data, err := v.Vault.Read(v.CurPath)
			if err != nil {
				dialog.ShowError(err, v.Window)
				return
			}
			outPath := filepath.Join(destRootDir, filepath.Base(v.CurPath))
			if err := os.WriteFile(outPath, data, 0644); err != nil {
				dialog.ShowError(err, v.Window)
				return
			}
			count = 1

		} else { // CASE 2: Folder or Entire Vault
			prefix := v.CurPath // "" for all, "dir/" for folder
			for plain := range v.Vault.PtoCtbl {
				if !strings.HasPrefix(plain, prefix) { // Filter by prefix
					continue
				}
				outArg := plain
				if prefix != "" {
					suffix := plain[len(prefix):]
					outArg = filepath.Join(filepath.Base(prefix), suffix)
				}
				outPath := filepath.Join(destRootDir, outArg)

				if strings.HasSuffix(plain, "/") {
					os.MkdirAll(outPath, 0755)
					continue
				}
				data, err := v.Vault.Read(plain)
				if err != nil {
					continue
				}
				os.MkdirAll(filepath.Dir(outPath), 0755)
				if err := os.WriteFile(outPath, data, 0644); err == nil {
					count++
				}
			}
		}
		dialog.ShowInformation("Export Result", fmt.Sprintf("Exported %d items to\n%s", count, destRootDir), v.Window)
	}, v.Window)
}

func (v *ViewPage) Rename() {
	if v.CurPath == "" {
		return
	}
	input := widget.NewEntry()
	if strings.HasSuffix(v.CurPath, "/") {
		input.SetText(v.CurPath[:len(v.CurPath)-1])
	} else if strings.Index(v.CurPath, "/") == -1 {
		input.SetText(v.CurPath)
	} else {
		input.SetText(v.CurPath[strings.LastIndex(v.CurPath, "/")+1:])
	}

	dialog.ShowCustomConfirm("Rename", "Rename", "Cancel", input, func(b bool) {
		if b {
			// 1. Sanitize input
			newName := input.Text
			replaceChars := []string{"\\", "/", ":", "*", "?", "\"", "<", ">", "|"}
			for _, char := range replaceChars {
				newName = strings.ReplaceAll(newName, char, "_")
			}
			if newName == "" {
				return
			}

			// 2. Construct new path
			parent := ""
			if idx := strings.LastIndex(strings.TrimSuffix(v.CurPath, "/"), "/"); idx != -1 {
				parent = v.CurPath[:idx+1]
			}
			newPath := parent + newName
			if strings.HasSuffix(v.CurPath, "/") {
				newPath += "/"
			}

			// 3. Rename
			if err := v.Vault.Rename(v.CurPath, newPath); err != nil {
				dialog.ShowError(err, v.Window)
				return
			}
			v.Tree.Refresh()
			v.CurPath = newPath // Update current path
			v.LblSelected.SetText(newPath)
		}
	}, v.Window)
}

func (v *ViewPage) Delete() {
	if v.CurPath == "" {
		return
	}
	dialog.ShowConfirm("Delete", "Delete "+v.CurPath+"?", func(b bool) {
		if b {
			if err := v.Vault.Del(v.CurPath); err != nil {
				dialog.ShowError(err, v.Window)
			}
			v.CurPath = ""
			v.LblSelected.SetText("")
			v.ContentArea.Objects = []fyne.CanvasObject{widget.NewLabelWithStyle("Select a file to view", fyne.TextAlignCenter, fyne.TextStyle{Italic: true})}
			v.ContentArea.Refresh()
			v.Tree.Refresh()
		}
	}, v.Window)
}

func (v *ViewPage) ResetPW() {
	// Create new window for password reset
	w := v.App.NewWindow("Reset Password")
	w.Resize(fyne.NewSize(400, 300))
	w.CenterOnScreen()

	// group0: keyfile selection
	var keyFile []byte
	lbl0 := widget.NewLabel("[0B 00000000] keyfile not selected")
	btn0a := widget.NewButtonWithIcon("Select", theme.FileIcon(), func() {
		dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
			if err == nil && r != nil {
				file, err := os.Open(r.URI().Path())
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				defer file.Close()
				buf := make([]byte, 1024)
				n, _ := io.ReadFull(file, buf)
				keyFile = buf[:n]
				lbl0.SetText(fmt.Sprintf("[%dB %s] %s", n, hex.EncodeToString(Opsec.Crc32(keyFile)), filepath.Base(r.URI().Path())))
			}
		}, w)
	})

	ent0 := widget.NewEntry()
	ent0.SetPlaceHolder("port: 8001")
	btn0b := widget.NewButtonWithIcon("Receive", theme.DownloadIcon(), func() {
		// 1. Get IP Address
		ips, err := GetIPs(true)
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		port := "8001"
		if ent0.Text != "" {
			port = ent0.Text
		}
		for i, r := range ips {
			ips[i] = r + ":" + port
		}
		dialog.ShowInformation("IP Address", strings.Join(ips, "\n"), w)

		// 2. Receive KeyFile
		go func() {
			listener, err := net.Listen("tcp", ":"+port)
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, w) })
				return
			}
			defer listener.Close()
			listener.(*net.TCPListener).SetDeadline(time.Now().Add(90 * time.Second)) // 90s timeout
			conn, err := listener.Accept()
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, w) })
				return
			}
			defer conn.Close()

			p := new(TPprotocol)
			p.Init(0, conn)
			fromPub, toPub, data, _, err := p.ReceiveData()
			if err != nil {
				fyne.Do(func() { dialog.ShowError(err, w) })
				return
			}

			// 3. Update UI
			fyne.Do(func() {
				keyFile = data
				crc0 := hex.EncodeToString(Opsec.Crc32(data))
				crc1 := hex.EncodeToString(Opsec.Crc32(fromPub))
				crc2 := hex.EncodeToString(Opsec.Crc32(toPub))
				lbl0.SetText(fmt.Sprintf("[%dB, %s] from %s to %s", len(data), crc0, crc1, crc2))
			})
		}()
	})
	box0 := container.NewBorder(nil, nil, container.NewHBox(btn0a, btn0b), nil, ent0)

	// group1: password entry
	ent1a := widget.NewPasswordEntry()
	ent1a.SetPlaceHolder("New Password")
	ent1b := widget.NewPasswordEntry()
	ent1b.SetPlaceHolder("Confirm Password")

	// group2: message entry, action button
	ent2 := widget.NewEntry()
	ent2.SetPlaceHolder("Vault Public Message")
	btn2 := widget.NewButtonWithIcon("Reset Password", theme.ConfirmIcon(), func() {
		if ent1a.Text != ent1b.Text {
			dialog.ShowError(errors.New("passwords do not match"), w)
			return
		}
		if err := v.Vault.StoreAccount(ent1a.Text, keyFile, ent2.Text); err != nil {
			dialog.ShowError(err, w)
		} else {
			dialog.ShowInformation("Success", "Password reset successfully.\nPlease restart using new credentials.", v.Window)
			w.Close()
		}
	})
	btn2.Importance = widget.HighImportance

	// group3: main layout
	box3 := container.NewVBox(
		lbl0,
		box0,
		widget.NewSeparator(),
		ent1a,
		ent1b,
		layout.NewSpacer(),
		ent2,
		btn2,
	)
	w.SetContent(container.NewPadded(box3))
	w.Show()
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			os.WriteFile("aft-panic.txt", []byte(fmt.Sprint(r)), 0644)
		}
	}()
	var p LoginPage
	p.Main(new(U1Config), new(AVault))
}
