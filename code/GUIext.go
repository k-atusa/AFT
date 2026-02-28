// test800 : project USAG GUI extension R2
package main

import (
	"bytes"
	"errors"
	"fmt"
	"image/color"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/k-atusa/USAG-Lib/Bencode"
	"github.com/k-atusa/USAG-Lib/Opsec"
	"github.com/ncruces/zenity"
)

// ===== theme =====
var FyneSize float32 = 1.0

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

func (m U1Theme) Font(s fyne.TextStyle) fyne.Resource     { return theme.DefaultTheme().Font(s) } // Fyne 2.7 has bug that can't render korean. Use v2.6.3 on Windows. See github.com/fyne-io/fyne/issues/6146
func (m U1Theme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (m U1Theme) Size(n fyne.ThemeSizeName) float32       { return theme.DefaultTheme().Size(n) * FyneSize }

// ===== zenity selection =====
var ZenNames []string = []string{"All", "Document", "Image", "Video", "Audio", "Archive"}
var ZenTypes [][]string = [][]string{
	[]string{"*"},
	[]string{"*.txt", "*.md", "*.pdf", "*.csv"},
	[]string{"*.jpg", "*.png", "*.jpeg", "*.webp", "*.svg", "*.gif", "*.bmp"},
	[]string{"*.mp4", "*.mkv", "*.mov", "*.webm", "*.avi"},
	[]string{"*.mp3", "*.wav", "*.flac", "*.ogg", "*.m4a"},
	[]string{"*.zip", "*.7z", "*.rar", "*.tar", "*.xz", "*.gz", "*.bz2"},
}

func zenityFilters() []zenity.FileFilter {
	var filters []zenity.FileFilter
	for i, name := range ZenNames {
		filters = append(filters, zenity.FileFilter{
			Name:     name,
			Patterns: ZenTypes[i],
		})
	}
	return filters
}

func ZenityFile(title string) (res string, err error) {
	if title == "" {
		title = "Select File"
	}
	res, err = zenity.SelectFile(zenity.Title(title), zenity.FileFilters(zenityFilters()))
	if res == "" {
		err = errors.New("canceled")
	}
	return res, err
}

func ZenityMultiFiles(title string) (res []string, err error) {
	if title == "" {
		title = "Select Files"
	}
	res, err = zenity.SelectFileMultiple(zenity.Title(title), zenity.FileFilters(zenityFilters()))
	if len(res) == 0 {
		err = errors.New("canceled")
	}
	return res, err
}

func ZenityFolder(title string) (res string, err error) {
	if title == "" {
		title = "Select Folder"
	}
	res, err = zenity.SelectFile(zenity.Title(title), zenity.Directory())
	if res == "" {
		err = errors.New("canceled")
	}
	return res, err
}

// ===== keyfile, keypair =====
func SelectKF(lbl *widget.Label, keyPtr *[]byte) {
	var data []byte = nil
	name := "keyfile not selected"

	// 1. open file
	path, err := ZenityFile("")
	var f *os.File
	if err == nil {
		f, err = os.Open(path)
		if err == nil {
			defer f.Close()
		}
	}

	// 2. Read file (max 1024 bytes)
	if err == nil {
		buf := make([]byte, 1024)
		n, _ := io.ReadFull(f, buf)
		data, name = buf[:n], filepath.Base(path)
	}

	// 2. Set Data & Update UI
	*keyPtr = data
	lbl.SetText(fmt.Sprintf("[%dB, %s] %s", len(data), Opsec.Crc32(data), name))
}

func ReceiveKF(w fyne.Window, lbl *widget.Label, portEnt *widget.Entry, keyPtr *[]byte) {
	// 1. Get IP Address
	ips, err := GetIPs(true)
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	port := "8001"
	if portEnt.Text != "" {
		port = portEnt.Text
	}
	for i, r := range ips {
		ips[i] = r + ":" + port
	}
	dialog.ShowInformation("IP Address", strings.Join(ips, "\n"), w)

	// 2. Receive KeyFile
	go func() {
		defer func() {
			if r := recover(); r != nil {
				os.WriteFile("panic-log.txt", []byte(fmt.Sprintf("panic while GUIext.ReceiveKF: %v", r)), 0644)
			}
		}()

		// 2-1. Make TCP Socket
		sock := new(TCPsocket)
		err := sock.MakeListener(port)
		defer sock.Close()
		if err != nil {
			fyne.Do(func() { dialog.ShowError(err, w) })
			return
		}

		// 2-2. Accept Connection
		tp := new(TP1)
		tp.Init(0, true, sock.Conn) // receiver does not need to set mode
		buf := new(bytes.Buffer)
		fromPub, toPub, _, err := tp.Receive(buf)
		data := buf.Bytes()
		if err != nil {
			fyne.Do(func() { dialog.ShowError(err, w) })
			return
		}

		// 3. Update UI
		fyne.Do(func() {
			*keyPtr = data
			lbl.SetText(fmt.Sprintf("[%dB, %s] from %s to %s", len(data), Opsec.Crc32(data), Opsec.Crc32(fromPub), Opsec.Crc32(toPub)))
		})
	}()
}

func ChooseKF(lbl *widget.Label, keyPtr *[]byte, sel string, mp map[string][]byte) {
	data, ok := mp[sel]
	if !ok {
		return
	}
	*keyPtr = data
	lbl.SetText(fmt.Sprintf("[%dB, %s] %s", len(data), Opsec.Crc32(data), sel))
}

func SelectPub(lbl *widget.Label, keyPtr *[]byte, basic []byte) {
	var data []byte = basic
	name := "default"

	// 1. open file
	path, err := ZenityFile("")
	var f *os.File
	if err == nil {
		f, err = os.Open(path)
		if err == nil {
			defer f.Close()
		}
	}

	// 2. Read & Decode file
	if err == nil {
		data, err = io.ReadAll(f)
		if err == nil {
			data, err = Bencode.Decode(string(data))
			if err == nil {
				name = filepath.Base(path)
			}
		}
	}
	if err != nil {
		name = fmt.Sprintf("default (%.20s)", err.Error())
	}

	// 2. Set Data & Update UI
	*keyPtr = data
	lbl.SetText(fmt.Sprintf("[%dB, %s] %s", len(data), Opsec.Crc32(data), name))
}

func ReceivePub(w fyne.Window, lbl *widget.Label, portEnt *widget.Entry, keyPtr *[]byte) {
	// 1. Get IP Address
	ips, err := GetIPs(true)
	if err != nil {
		dialog.ShowError(err, w)
		return
	}
	port := "8001"
	if portEnt.Text != "" {
		port = portEnt.Text
	}
	for i, r := range ips {
		ips[i] = r + ":" + port
	}
	dialog.ShowInformation("IP Address", strings.Join(ips, "\n"), w)

	// 2. Receive KeyFile
	go func() {
		defer func() {
			if r := recover(); r != nil {
				os.WriteFile("panic-log.txt", []byte(fmt.Sprintf("panic while GUIext.ReceivePub: %v", r)), 0644)
			}
		}()

		// 2-1. Make TCP Socket
		sock := new(TCPsocket)
		err := sock.MakeListener(port)
		defer sock.Close()
		if err != nil {
			fyne.Do(func() { dialog.ShowError(err, w) })
			return
		}

		// 2-2. Accept Connection
		tp := new(TP1)
		tp.Init(0, true, sock.Conn) // receiver does not need to set mode
		buf := new(bytes.Buffer)
		fromPub, toPub, _, err := tp.Receive(buf)
		data := buf.Bytes()
		if err != nil {
			fyne.Do(func() { dialog.ShowError(err, w) })
			return
		}

		// 3. Decode key
		data, err = Bencode.Decode(string(data))
		if err != nil {
			fyne.Do(func() { dialog.ShowError(err, w) })
			return
		}

		// 4. Update UI
		fyne.Do(func() {
			*keyPtr = data
			lbl.SetText(fmt.Sprintf("[%dB, %s] from %s to %s", len(data), Opsec.Crc32(data), Opsec.Crc32(fromPub), Opsec.Crc32(toPub)))
		})
	}()
}

// ===== File List Manager =====
func ListAddFile(l *widget.List, tgts *[]string) {
	defer l.Refresh()
	paths, err := ZenityMultiFiles("")
	if err != nil {
		return
	}
	for _, r := range paths {
		if slices.Contains(*tgts, r) {
			continue
		}
		*tgts = append(*tgts, r)
	}
}

func ListAddFolder(l *widget.List, tgts *[]string) {
	defer l.Refresh()
	path, err := ZenityFolder("")
	if err != nil {
		return
	}
	if slices.Contains(*tgts, path) {
		return
	}
	*tgts = append(*tgts, path)
}

func ListDelTgt(l *widget.List, tgts *[]string, idx int) {
	defer l.Refresh()
	if idx < 0 || idx > len(*tgts) {
		return
	}
	if idx == len(*tgts) {
		*tgts = make([]string, 0)
	} else {
		*tgts = append((*tgts)[:idx], (*tgts)[idx+1:]...)
	}
}

// ===== Others =====
func TrimStr(s string, line int) string {
	if line <= 0 {
		return s
	}
	var b strings.Builder
	for i, r := range []rune(s) {
		if i > 0 && i%line == 0 {
			b.WriteRune('\n')
		}
		b.WriteRune(r)
	}
	return b.String()
}
