# AFT-desktop v1.0.0

project USAG: Advanced File Transfer desktop version

> AFT is simple secure storage for keeping important data and secrets safe.

## CLI Usage

| Option | Input | Info | 정보 |
| :--- | :--- | :--- | :--- |
| -m | import, export, view, trim | Sets the working mode. | 작업 모드를 설정합니다. |
| -o | dirpath | Sets the output path. | 출력 경로를 설정합니다. |
| -algo | arg1, pbk1 | Sets the encryption algorithm. | 암호화 알고리즘을 설정합니다. |
| -img | webp, png, bin | Sets the image format. | 위장 이미지 형식을 설정합니다. |
| -pw | text | Sets the password. | 비밀번호를 설정합니다. |
| -kf | filepath | Sets the key file path. | 키 파일 경로를 설정합니다. |
| -msg | text | Sets public message of vault. | 저장소의 공개 메세지를 설정합니다. |
| | | Argument following the options are interpreted as target path. | 옵션 이후 인자는 타겟 경로로 해석됩니다. |

- import: 타겟 폴더를 암호화하여 새 저장소를 생성합니다. Make new vault by encrypting target folder.
- export: 볼트를 복호화하여 원본 폴더를 생성합니다. Decrypt vault and generate original folder.
- view: 볼트의 메타데이터와 파일 리스트를 출력합니다. Print vault metadata and files list.
- trim: 볼트의 논리적 구조와 파일시스템의 물리적 구조를 동기화하고 암호화 키 쌍을 새 것으로 교체합니다. Sync logical structure of vault with physical file system, replace encryption key pair to new one.

CLI version does not support file transfer function. However, trim function is supported only with CLI version.

## GUI Usage

| function | Info | 정보 |
| :--- | :--- | :--- |
| Import File | Imports a file into the encrypted vault. | 볼트로 파일을 가져옵니다. |
| Import Folder | Imports a directory into the vault recursively. | 볼트로 폴더를 가져옵니다. |
| Export | Exports files or folders from the vault to the local system. | 볼트에서 폴더나 파일을 내보냅니다. |
| Rename | Renames the selected item within the vault. | 선택 항목의 이름을 바꿉니다. |
| Delete | Deletes the selected item from the vault. | 선택 항목을 삭제합니다. |
| TrSend | Transfers a file in "KeyFile" mode (partial data). | 키 파일 모드로 파일을 전송합니다. |
| Send | Transfers a file in "Lossless" mode (complete data). | 무손실 모드로 파일을 전송합니다. |
| Reset Password | Resets the vault password **without changing public keys.** | 볼트의 비밀번호를 재설정합니다. **공개키는 교체되지 않습니다.** |
| Extend | Extends the login session. | 로그인 세션을 연장합니다. |
| Logout | Terminates the login session. | 로그인 세션을 종료합니다. |

- config.json에 단축 경로를 지정하고 자동 세션 만료 여부를 설정할 수 있습니다. You can specify shortcut paths and toggle the automatic session expiration in the config.json file.
- 네트워크 송수신 시 입력창을 비워 놓으면 기본 포트가 사용됩니다. If you leave the input field empty during network transmission, the default port will be used.
- 로그인 화면 좌측은 기존 저장소에 로그인하는 기능이며, 우측은 새 저장소를 생성하는 기능입니다. The left side of the login screen is for logging into an existing vault, and the right side is for creating a new vault.
- 뷰어 화면에서 파일 목록을 확인하고 텍스트와 이미지 데이터를 볼 수 있습니다. You can view the file list and text/image data in the viewer screen.

**KeyFile is supposed to be smaller than 1024 bytes. Send function cuts the file if it is larger than 1024 bytes.**

**Empty password and keyfile are allowed to maximize user control.**

## Build Executable

This application uses Go programming language. [Install Go](https://go.dev/) to build yourself, or download pre-built release binary. It takes few minutes to download and build GUI version.

windows cli
```bat
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o aft-lite.exe AFTcore.go lite.go
```

linux/mac cli
```bash
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o aft-lite AFTcore.go lite.go
```

windows gui
```bat
go mod init example.com
go mod tidy
go build -ldflags="-H windowsgui -s -w" -trimpath -o aft.exe TP1.go GUIext.go AFTcore.go main.go
```

linux/mac gui
```bash
go mod init example.com
go mod tidy
go build -ldflags="-s -w" -trimpath -o aft TP1.go GUIext.go AFTcore.go main.go
```

fyne2 GUI requires C compiler and X11 environment. check and install following packages before build.
```bash
gcc --version
sudo apt-get install pkg-config libgl1-mesa-dev libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev libxi-dev libxxf86vm-dev
```
