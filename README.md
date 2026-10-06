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
the compiler directly. The sources also use two Windows-only APIs and rely on a
transitive include, so three small edits are required first.

**1. Install the dependencies:**

```sh
sudo apt install build-essential libssl-dev
```

**2. Replace `<conio.h>` and `_getch()`.** `conio.h` does not exist on Linux. Swap the
include at `HardEncDec.cpp:10` for a termios-based single-character read, and change both
`_getch()` calls (lines 98 and 118) to `hardencdec_getch()`:

```cpp
#include <termios.h>
#include <unistd.h>

static char hardencdec_getch() {
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    char ch = 0;
    ssize_t n = read(STDIN_FILENO, &ch, 1);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    if (n <= 0) return (char)13;
    return ch == (char)10 ? (char)13 : ch;
}
```

This keeps the masked password prompt working and still returns `\r` on Enter, which is
what the existing loops compare against.

**3. Change `system("cls")` to `system("clear")`** at `HardEncDec.cpp:437`.

**4. Add `#include <algorithm>` to `EncDecUtils.cpp`.** `toLower()` calls
`std::transform` without the include; MSVC supplies it transitively, g++ does not and
fails with `'transform' is not a member of 'std'`.

Then build:

```sh
g++ -std=c++20 -O2 HardEncDec.cpp EncDecUtils.cpp -lcrypto -o HardEncDec
```

Only `-lcrypto` is needed; the tool uses no TLS APIs. Expect one warning from
`system("clear")` about an unused return value, which is harmless.