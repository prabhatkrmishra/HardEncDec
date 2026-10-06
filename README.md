# HardEncDec

A Windows console tool that encrypts and decrypts files with **AES-256-GCM**.
The encryption key is derived from a password using **PBKDF2-HMAC-SHA256** with a
per-file random salt.

## Usage

Run `HardEncDec.exe` and choose from the menu:

1. Generate a 64-character key and save it as `password.key`
2. Encrypt/decrypt a file

You can also drop a file onto the executable, or pass it as the first argument:

```
HardEncDec.exe "C:\path\to\file.txt"
```

The operation is chosen from the file extension — a file **not** ending in `.enc` is
encrypted, one ending in `.enc` is decrypted. Encryption appends `.enc` to the name;
decryption strips it.

When prompted, choose `(p)` to type a password interactively (it is masked and must be
confirmed) or `(k)` to read the password from `password.key`.

## File format (version 3)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 byte | File version (`3`) |
| 1 | 16 bytes | Random salt |
| 17 | 12 bytes | Random GCM IV |
| 29 | variable | AES-256-GCM ciphertext |
| end | 16 bytes | GCM authentication tag |

A 16-byte authentication tag is appended to every file, so any modification to the
ciphertext is detected on decryption and reported as a wrong-password-or-tampered-file
error. Decryption is streamed in 512 KB chunks and does not load the whole file into
memory.

## Version compatibility

**This build reads and writes version 3 only.** There is no backward compatibility with
earlier versions.

Files written by V1.0 and V2.0 cannot be decrypted by the current build, and this is not
a bug that will be fixed in place: those releases derived their key with 10 million
PBKDF2 iterations, while version 3 uses 100 million, and the header does not record which
count was used. To read an older file, use the matching older release of this tool.

The same applies going forward. Bumping `FILE_VERSION` in `EncDecUtils.h` permanently
strands every file written before the bump, because the format carries no field that
records the parameters needed to reproduce the key.

## Building

### Windows

Visual Studio 2022 (v143), C++20. The project links OpenSSL statically from
`C:\OpenSSL-Win64` — both the include and library paths are set in `HardEncDec.vcxproj`
for the x64 Debug and Release configurations and need adjusting for your machine.
Release x64 uses the static CRT (`MultiThreaded`).

### Linux

There is no Makefile or CMake project — `HardEncDec.sln` is MSBuild-only — so build with
the compiler directly. Console input is handled in `EncDecUtils.cpp`: `conio.h` and
`_getch()` on Windows, `termios` on POSIX, behind `#ifdef _WIN32`, so the same sources
build on both.

```sh
sudo apt install build-essential libssl-dev
g++ -std=c++20 -O2 HardEncDec/HardEncDec.cpp HardEncDec/EncDecUtils.cpp -lcrypto -o HardEncDec
```

Only `-lcrypto` is needed; the tool uses no TLS APIs. The build is warning-clean under
`-Wall -Wextra`.

### Temporary files

Output is written to a randomly named scratch file beside the target and moved into place
only once the AES-GCM tag verifies, so an existing file is never destroyed by a failed
run or a wrong password. If the process is killed outright, a `*.hedtmp` file may be left
behind; it is safe to delete.
