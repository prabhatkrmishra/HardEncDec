#include <algorithm>
#include <cctype>
#include <filesystem>
#include <random>
#ifdef _WIN32
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "EncDecUtils.h"

std::string generateRandomPassword(size_t length) {
    static const std::string allowedChars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~";

    // A newline in the charset would be silently truncated by readKey, so the key
    // typed back would never match the key on disk.
    if (allowedChars.empty() || allowedChars.size() > 256 ||
        allowedChars.find('\n') != std::string::npos ||
        allowedChars.find('\r') != std::string::npos) {
        throw std::runtime_error("Password character set is invalid");
    }

    std::string password;
    password.reserve(length);

    while (password.size() < length) {
        unsigned char buf[64];
        size_t want = std::min(sizeof(buf), length - password.size());
        if (RAND_bytes(buf, static_cast<int>(want)) != 1) {
            throw std::runtime_error("Random number generation failed");
        }
        for (size_t i = 0; i < want; ++i) {
            // 256 is not a multiple of the set size, so taking a plain modulo would
            // make the first characters measurably more likely than the rest.
            if (buf[i] >= allowedChars.size()) continue;
            password.push_back(allowedChars[buf[i]]);
        }
    }
    return password;
}

void saveKey(const std::string& key, const std::string& filename) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) {
        throw std::runtime_error("Cannot open file for writing: " + filename);
    }

    out << key;
    if (!out.good()) {
        throw std::runtime_error("Error writing to file: " + filename);
    }
    out.close();

#ifndef _WIN32
    // The key file is a plaintext secret; do not leave it world readable.
    std::error_code ec;
    std::filesystem::permissions(filename,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
#endif
}

std::string readKey(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Cannot open file for reading: " + filename);
    }

    std::string key;
    std::getline(in, key);
    in.close();

    // A key file written on Windows keeps its CR, which would become part of the
    // password here and make every decryption fail.
    while (!key.empty() && (key.back() == '\r' || key.back() == '\n')) {
        key.pop_back();
    }

    if (key.empty()) {
        throw std::runtime_error("Key file is empty: " + filename);
    }

    return key;
}


bool fileExists(const std::string& filename) {
    // A directory opens successfully as an ifstream, so opening is not proof that the
    // path is a readable input. Only regular files are valid here.
    std::error_code ec;
    return std::filesystem::is_regular_file(filename, ec);
}

bool askOverwrite(const std::string& filename) {
    if (fileExists(filename)) {
        std::string response = getInput("=> Output file exists. Overwrite? (y/n): ");
        return (response == "y" || response == "Y");
    }
    return true;
}

// Smallest file that can be a valid encrypted file: version + salt + iv + tag.
static const std::streamsize MIN_ENCRYPTED_SIZE = sizeof(uint8_t) + SALT_SIZE + AES_IVLEN + TAG_SIZE;

// Reads the leading version byte, or -1 if the file is missing or too short.
static int readFileVersion(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) return -1;

    std::streamsize size = file.tellg();
    if (size < MIN_ENCRYPTED_SIZE) return -1;

    file.seekg(0, std::ios::beg);
    uint8_t version = 0;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (file.gcount() != static_cast<std::streamsize>(sizeof(version))) return -1;
    return static_cast<int>(version);
}

bool isValidEncryptedFile(const std::string& filename) {
    return readFileVersion(filename) == FILE_VERSION;
}

// Only the current format is readable. Files from older releases cannot be decrypted
// because the header does not record the PBKDF2 iteration count that derived the key.
void explainUnsupportedVersion(int version) {
    std::cout << "Unsupported file version: " << version
        << " (supported version: " << static_cast<int>(FILE_VERSION) << ")" << std::endl;
    if (version > 0 && version < FILE_VERSION) {
        std::cout << "Please use the older release V" << version
            << ".0 of this tool to decrypt it." << std::endl;
    }
    else {
        std::cout << "This does not look like a file encrypted by this tool." << std::endl;
    }
}

bool isEncryptedFile(const std::string& filename) {
    return filename.size() > 4 && toLower(filename).substr(filename.size() - 4) == ".enc";
}

// Returns the next keystroke, or -1 for "no character": end of input, or an extended
// key such as an arrow whose scan code must never become user input.
static int readKeyChar() {
#ifdef _WIN32
    int c = _getch();
    if (c == (EOF)) {
        // No console attached: fall back to buffered input so piped usage still works.
        int c2 = std::cin.get();
        if (c2 == EOF) return -1;
        return c2 == '\n' ? '\r' : c2;
    }
    if (c == 0 || c == 224) {
        _getch();
        return -1;
    }
    return c;
#else
    struct termios oldTerm, newTerm;
    if (tcgetattr(STDIN_FILENO, &oldTerm) != 0) {
        // Not a terminal: there is no echo to suppress, so buffered reads are fine.
        int c = std::cin.get();
        if (c == EOF) return -1;
        if (c == '\n') return '\r';
        if (c == 0x7F) return 8;
        return c;
    }
    newTerm = oldTerm;
    newTerm.c_lflag &= ~(ICANON | ECHO);
    newTerm.c_cc[VMIN] = 1;
    newTerm.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) != 0) return -1;

    unsigned char ch = 0;
    ssize_t n = read(STDIN_FILENO, &ch, 1);
    int result = -1;
    if (n == 1) {
        if (ch == 0x1B) {
            newTerm.c_cc[VMIN] = 0;
            newTerm.c_cc[VTIME] = 1;
            if (tcsetattr(STDIN_FILENO, TCSANOW, &newTerm) == 0) {
                char seq[8];
                ssize_t got = read(STDIN_FILENO, seq, sizeof(seq));
                (void)got;
            }
        }
        else if (ch == '\n') result = '\r';
        else if (ch == 0x7F) result = 8;
        else result = static_cast<unsigned char>(ch);
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldTerm);
    return result;
#endif
}

static bool g_inputClosed = false;

// True once a read hit end of input, so a menu loop can exit instead of spinning
// on a stream that will never produce another line.
bool inputClosed() {
    return g_inputClosed;
}

// Every prompt in the program reads through here. Mixing std::getline with raw reads
// on stdin leaves two buffers on the same descriptor, and the getline buffer swallows
// input meant for the raw reader.
bool readInputLine(std::string& out, const std::string& prompt, bool masked) {
    out.clear();
    // The prompt has no newline, and the next thing we do is switch the terminal into
    // raw mode where nothing flushes for us, so it has to go out before we read.
    std::cout << prompt << std::flush;
    while (true) {
        int ch = readKeyChar();
        if (ch < 0) {
            std::cout << std::endl;
            g_inputClosed = true;
            return false;
        }
        if (ch == '\r') {
            std::cout << std::endl;
            g_inputClosed = false;
            return true;
        }
        if (ch == 8) {
            if (!out.empty()) {
                out.pop_back();
                if (masked) std::cout << "\b \b";
            }
        }
        else if (ch >= 32 && ch < 127) {
            out.push_back(static_cast<char>(ch));
            std::cout << (masked ? '*' : static_cast<char>(ch));
        }
    }
}

// One keypress, no Enter. Used by the menu so choosing an option acts immediately.
int readImmediateKey() {
    return readKeyChar();
}

std::string getInput(const std::string& prompt) {
    std::string input;
    readInputLine(input, prompt, false);
    return input;
}

std::string toLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

std::string getOutputFilename(const std::string& inputFilename, bool encrypt) {
    if (encrypt) {
        return inputFilename + ".enc";
    }
    else {
        if (isEncryptedFile(inputFilename)) {
            std::string stripped = inputFilename.substr(0, inputFilename.size() - 4);
            if (!stripped.empty()) {
                return stripped;
            }
        }
        return inputFilename + ".decrypted";
    }
}

void showProgress(std::streamsize current, std::streamsize total, const std::string& operation) {
    if (total <= 0) return;

    const int barWidth = 50;
    double ratio = static_cast<double>(current) / static_cast<double>(total);
    // A file that grew while we were reading it pushes the ratio past 1, which would
    // put the cursor outside the bar and leave it with nothing to draw.
    if (ratio < 0.0) ratio = 0.0;
    if (ratio > 1.0) ratio = 1.0;
    int pos = static_cast<int>(barWidth * ratio);
    int percentage = static_cast<int>(ratio * 100);

    std::string bar;

    if (operation == "Encryption") {
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) bar += "#";
            else if (i == pos) bar += "|>";
            else bar += "-";
        }
    }
    else if (operation == "Decryption") {
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) bar += "-";
            else if (i == pos) bar += "|>";
            else bar += "#";
        }
    }
    else {
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) bar += "=";
            else if (i == pos) bar += ">";
            else bar += " ";
        }
    }

    std::cout << "\r[" << operation << "] [" << bar << "] "
        << std::setw(3) << percentage << "% "
        << "(" << current << "/" << total << " bytes)";
    std::cout.flush();

    if (current >= total) std::cout << std::endl;
}
