// test800 : project USAG GUI extension
package main

import (
	"bytes"
	"fmt"
	"image/color"
	"io"
	"os"
	"slices"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/k-atusa/USAG-Lib/Bencode"
	"github.com/k-atusa/USAG-Lib/Opsec"
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

func (m U1Theme) Font(s fyne.TextStyle) fyne.Resource     { return theme.DefaultTheme().Font(s) }
func (m U1Theme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }
func (m U1Theme) Size(n fyne.ThemeSizeName) float32       { return theme.DefaultTheme().Size(n) * FyneSize }

// ===== keyfile, keypair =====
func SelectKF(w fyne.Window, lbl *widget.Label, keyPtr *[]byte) {
	dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
		if err == nil && r != nil {
			// 1. Read file (max 1024 bytes)
			defer r.Close()
			buf := make([]byte, 1024)
			n, _ := io.ReadFull(r, buf)
			data := buf[:n]

			// 2. Set Data & Update UI
			*keyPtr = data
			lbl.SetText(fmt.Sprintf("[%dB, %s] %s", n, Opsec.Crc32(data), r.URI().Name()))
		} else {
			*keyPtr = nil
			lbl.SetText("[0B 00000000] keyfile not selected")
		}
	}, w)
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

func SelectPub(w fyne.Window, lbl *widget.Label, keyPtr *[]byte, basic []byte) {
	dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
		data := basic
		name := "default"
		if err == nil && r != nil {
			defer r.Close()
			data, err = io.ReadAll(r)
			name = r.URI().Name()
			if err != nil {
				data = basic
				name = fmt.Sprintf("default (%.20s)", err.Error())
			} else {
				data, err = Bencode.Decode(string(data))
				if err != nil {
					data = basic
					name = fmt.Sprintf("default (%.20s)", err.Error())
				}
			}
		}
		*keyPtr = data
		lbl.SetText(fmt.Sprintf("[%dB, %s] %s", len(data), Opsec.Crc32(data), name))
	}, w)
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
func ListAddFile(w fyne.Window, l *widget.List, tgts *[]string) {
	dialog.ShowFileOpen(func(r fyne.URIReadCloser, err error) {
		defer l.Refresh()
		if err == nil && r != nil {
			path := r.URI().Path()
			if slices.Contains(*tgts, path) {
				return
			}
			*tgts = append(*tgts, path)
		}
	}, w)
}

func ListAddFolder(w fyne.Window, l *widget.List, tgts *[]string) {
	dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
		defer l.Refresh()
		if err == nil && lu != nil {
			path := lu.Path()
			if slices.Contains(*tgts, path) {
				return
			}
			*tgts = append(*tgts, path)
		}
	}, w)
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
