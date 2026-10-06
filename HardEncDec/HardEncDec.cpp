#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <memory>
#include <stdexcept>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <filesystem>

#include "EncDecUtils.h"
#include <ranges>
#include <algorithm>

// Zeroes itself on destruction, so the derived key and plaintext chunks do not
// survive in freed heap when an error aborts the operation part way through.
class SecretBuffer {
public:
    SecretBuffer() = default;
    explicit SecretBuffer(size_t n) : data_(n) {}

    ~SecretBuffer() {
        if (!data_.empty()) {
            OPENSSL_cleanse(data_.data(), data_.size());
        }
    }

    unsigned char* data() { return data_.data(); }
    const unsigned char* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }

    SecretBuffer(const SecretBuffer&) = delete;
    SecretBuffer& operator=(const SecretBuffer&) = delete;

    SecretBuffer(SecretBuffer&& other) noexcept : data_(std::move(other.data_)) {}

private:
    std::vector<unsigned char> data_;
};

class SecureString {
private:
    std::vector<char> data;

public:
    SecureString() = default;

    SecureString(const std::string& str) {
        assign(str);
    }

    void assign(const std::string& str) {
        data.assign(str.begin(), str.end());
        data.push_back('\0');
    }

    const char* c_str() const {
        return data.data();
    }

    size_t size() const {
        return data.empty() ? 0 : data.size() - 1;
    }

    bool empty() const {
        return data.size() <= 1;
    }

    ~SecureString() {
        if (!data.empty()) {
            OPENSSL_cleanse(data.data(), data.size());
        }
    }

    // Prevent copying
    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    // Allow moving
    SecureString(SecureString&& other) noexcept : data(std::move(other.data)) {}
    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            if (!data.empty()) {
                OPENSSL_cleanse(data.data(), data.size());
            }
            data = std::move(other.data);
        }
        return *this;
    }
};

static void handleOpenSSLError(const std::string& operation) {
    char errorBuf[256];
    ERR_error_string_n(ERR_get_error(), errorBuf, sizeof(errorBuf));
    throw std::runtime_error(operation + " failed: " + std::string(errorBuf));
}

static SecretBuffer deriveKey(const SecureString& password, const std::vector<unsigned char>& salt) {
    SecretBuffer key(AES_KEYLEN);

    if (!PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
        salt.data(), static_cast<int>(salt.size()),
        PBKDF2_ITERATIONS, EVP_sha256(),
        static_cast<int>(key.size()), key.data())) {
        handleOpenSSLError("Key derivation");
    }
    return key;
}

static bool getPassword(const std::string& operation, SecureString& password) {
    std::string tempPassword;
    std::string confirmPassword;

    auto scrub = [&]() {
        OPENSSL_cleanse(tempPassword.data(), tempPassword.size());
        OPENSSL_cleanse(confirmPassword.data(), confirmPassword.size());
    };

    while (true) {
        if (!readInputLine(tempPassword, "=> Enter password for " + operation + ": ", true)) {
            scrub();
            return false;
        }

        if (tempPassword.empty()) {
            scrub();
            std::cout << "Password cannot be empty. Please try again." << std::endl;
            continue;
        }

        if (!readInputLine(confirmPassword, "=> Confirm password for " + operation + ": ", true)) {
            scrub();
            return false;
        }

        if (tempPassword == confirmPassword) {
            break;
        }

        scrub();
        std::cout << "\n[INVALID] Passwords do not match. Please try again.\n" << std::endl;
    }

    password.assign(tempPassword);
    scrub();

    return true;
}

static std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
createCipherContext(const EVP_CIPHER* cipher, const unsigned char* key,
    const unsigned char* iv, int encrypt) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!ctx) {
        throw std::runtime_error("[ERROR] Failed to create cipher context");
    }

    if (!EVP_CipherInit_ex(ctx.get(), cipher, nullptr, key, iv, encrypt)) {
        handleOpenSSLError("Cipher initialization");
    }

    return ctx;
}

// Writes to a scratch file beside the target and moves it into place only on commit.
// Opening the target directly truncates it before the password is known to be correct,
// destroying an existing file whenever the operation failed or was interrupted.
class AtomicOutput {
public:
    explicit AtomicOutput(const std::string& targetPath) : targetPath_(targetPath) {
        // A random name keeps concurrent runs from colliding and stops a name planted
        // at the target path from being followed.
        for (int attempt = 0; attempt < 16; ++attempt) {
            unsigned char suffix[8];
            if (RAND_bytes(suffix, sizeof(suffix)) != 1) {
                throw std::runtime_error("[ERROR] Random number generation failed");
            }
            static const char* hex = "0123456789abcdef";
            std::string name;
            for (unsigned char b : suffix) {
                name += hex[b >> 4];
                name += hex[b & 0x0F];
            }
            tempPath_ = targetPath_ + "." + name + ".hedtmp";
            std::error_code existsEc;
            if (!std::filesystem::exists(tempPath_, existsEc)) {
                break;
            }
            tempPath_.clear();
        }
        if (tempPath_.empty()) {
            throw std::runtime_error("[ERROR] Could not create a unique temporary file");
        }

        stream_.open(tempPath_, std::ios::binary | std::ios::trunc);
        if (!stream_) {
            // The destructor does not run for a constructor that throws.
            std::error_code removeEc;
            std::filesystem::remove(tempPath_, removeEc);
            throw std::runtime_error("[ERROR] Could not create temporary file: " + tempPath_);
        }
    }

    ~AtomicOutput() {
        if (!committed_) {
            if (stream_.is_open()) {
                stream_.close();
            }
            std::error_code ec;
            std::filesystem::remove(tempPath_, ec);
        }
    }

    std::ofstream& stream() { return stream_; }

    // Closes the scratch file and moves it over the target, returning the byte count.
    // Throws on any failure, leaving removal of the scratch file to the destructor.
    std::uintmax_t commit() {
        stream_.flush();
        if (!stream_.good()) {
            throw std::runtime_error("[ERROR] Error writing to output file");
        }
        stream_.close();
        if (stream_.fail()) {
            throw std::runtime_error("[ERROR] Error closing output file");
        }

        std::error_code ec;
        std::uintmax_t size = std::filesystem::file_size(tempPath_, ec);
        if (ec) {
            throw std::runtime_error("[ERROR] Could not read output file size: " + tempPath_);
        }

        // std::filesystem::rename replaces an existing target on Windows, which the
        // C rename() does not.
        std::filesystem::rename(tempPath_, targetPath_, ec);
        if (ec) {
            throw std::runtime_error("[ERROR] Could not replace output file: " + targetPath_);
        }

        committed_ = true;
        return size;
    }

    AtomicOutput(const AtomicOutput&) = delete;
    AtomicOutput& operator=(const AtomicOutput&) = delete;

private:
    std::string targetPath_;
    std::string tempPath_;
    std::ofstream stream_;
    bool committed_ = false;
};

static void aesEncryptFile(const std::string& inputFilename, const std::string& outputFilename, const SecureString& password) {
    if (!fileExists(inputFilename)) {
        throw std::runtime_error("[ERROR] Input file does not exist: " + inputFilename);
    }

    std::ifstream inputFile(inputFilename, std::ios::binary);
    if (!inputFile) {
        throw std::runtime_error("[ERROR] Could not open input file: " + inputFilename);
    }

    // Get file size for progress reporting
    inputFile.seekg(0, std::ios::end);
    std::streamsize fileSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);
    if (fileSize < 0) {
        throw std::runtime_error("[ERROR] Could not determine size of input file: " + inputFilename);
    }

    AtomicOutput output(outputFilename);
    std::ofstream& outputFile = output.stream();

    // Write file version
    outputFile.write(reinterpret_cast<const char*>(&FILE_VERSION), sizeof(FILE_VERSION));

    // Generate salt and IV
    std::vector<unsigned char> salt(SALT_SIZE);
    std::vector<unsigned char> iv(AES_IVLEN);

    if (RAND_bytes(salt.data(), SALT_SIZE) != 1 || RAND_bytes(iv.data(), AES_IVLEN) != 1) {
        throw std::runtime_error("[ERROR] Random number generation failed");
    }

    outputFile.write(reinterpret_cast<const char*>(salt.data()), SALT_SIZE);
    outputFile.write(reinterpret_cast<const char*>(iv.data()), AES_IVLEN);

    // Derive key from password
    SecretBuffer key = deriveKey(password, salt);

    // Initialize encryption context
    auto ctx = createCipherContext(EVP_aes_256_gcm(), key.data(), iv.data(), 1);

    SecretBuffer buffer(BUFFER_SIZE);
    SecretBuffer encryptedBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    std::streamsize totalRead = 0;
    int len;

    // Encrypt file data
    std::cout << "\n";
    while (inputFile.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE) || inputFile.gcount() > 0) {
        std::streamsize bytesRead = inputFile.gcount();
        totalRead += bytesRead;

        if (!EVP_CipherUpdate(ctx.get(), encryptedBuffer.data(), &len, buffer.data(), static_cast<int>(bytesRead))) {
            throw std::runtime_error("[ERROR] Encryption update failed");
        }
        outputFile.write(reinterpret_cast<const char*>(encryptedBuffer.data()), len);
        showProgress(totalRead, fileSize, "Encryption");
    }

    // Finalize encryption
    if (!EVP_CipherFinal_ex(ctx.get(), encryptedBuffer.data(), &len)) {
        throw std::runtime_error("[ERROR] Encryption finalization failed");
    }
    outputFile.write(reinterpret_cast<const char*>(encryptedBuffer.data()), len);

    // Get and write authentication tag
    unsigned char tag[TAG_SIZE];
    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag)) {
        throw std::runtime_error("[ERROR] Failed to get authentication tag");
    }
    outputFile.write(reinterpret_cast<const char*>(tag), TAG_SIZE);

    output.commit();

    std::cout << "\n[DONE] Encryption successful!\n[DONE] File saved as: " << outputFilename << std::endl;
}

static void aesDecryptFile(const std::string& inputFilename, const std::string& outputFilename, const SecureString& password) {
    std::ifstream inputFile(inputFilename, std::ios::binary);
    if (!inputFile) {
        throw std::runtime_error("[ERROR] Could not open input file: " + inputFilename);
    }

    // Read and validate version
    uint8_t fileVersion;
    inputFile.read(reinterpret_cast<char*>(&fileVersion), sizeof(fileVersion));
    if (!inputFile) {
        throw std::runtime_error("[ERROR] Failed to read file version");
    }

    // Only the current format is readable. Files from older releases cannot be
    // decrypted because the header does not record the PBKDF2 iteration count
    // that derived their key.
    if (fileVersion != FILE_VERSION) {
        explainUnsupportedVersion(fileVersion);
        throw std::runtime_error("[ERROR] Cannot decrypt " + inputFilename);
    }

    // Read salt
    std::vector<unsigned char> salt(SALT_SIZE);
    inputFile.read(reinterpret_cast<char*>(salt.data()), SALT_SIZE);
    if (inputFile.gcount() != SALT_SIZE) {
        throw std::runtime_error("[ERROR] Failed to read salt: expected " +
            std::to_string(SALT_SIZE) + " bytes, got " +
            std::to_string(inputFile.gcount()));
    }

    // Read IV
    std::vector<unsigned char> iv(AES_IVLEN);
    inputFile.read(reinterpret_cast<char*>(iv.data()), AES_IVLEN);
    if (inputFile.gcount() != AES_IVLEN) {
        throw std::runtime_error("[ERROR] Failed to read IV: expected " +
            std::to_string(AES_IVLEN) + " bytes, got " +
            std::to_string(inputFile.gcount()));
    }

    // Get file size
    inputFile.seekg(0, std::ios::end);
    std::streamsize fileSize = inputFile.tellg();
    if (fileSize < 0) {
        throw std::runtime_error("[ERROR] Could not determine size of input file: " + inputFilename);
    }

    // Calculate ciphertext size (excluding header and tag)
    std::streamsize headerSize = sizeof(fileVersion) + SALT_SIZE + AES_IVLEN + TAG_SIZE;
    if (fileSize < headerSize) {
        throw std::runtime_error("[ERROR] File too small to be a valid encrypted file");
    }

    std::streamsize ciphertextSize = fileSize - headerSize;

    // Seek back to start of ciphertext
    inputFile.seekg(sizeof(fileVersion) + SALT_SIZE + AES_IVLEN, std::ios::beg);

    // Derive key from password
    SecretBuffer key = deriveKey(password, salt);

    // Initialize decryption context
    auto ctx = createCipherContext(EVP_aes_256_gcm(), key.data(), iv.data(), 0);

    AtomicOutput output(outputFilename);
    std::ofstream& outputFile = output.stream();

    SecretBuffer buffer(BUFFER_SIZE);
    SecretBuffer decryptedBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    std::streamsize totalRead = 0;
    int len;

    // Read and decrypt file data in chunks
    std::cout << "\n";
    while (ciphertextSize > 0) {
        std::streamsize readSize = std::min(ciphertextSize, static_cast<std::streamsize>(BUFFER_SIZE));
        inputFile.read(reinterpret_cast<char*>(buffer.data()), readSize);
        std::streamsize bytesRead = inputFile.gcount();

        if (bytesRead <= 0) break;

        // Decrypt the chunk
        if (!EVP_CipherUpdate(ctx.get(), decryptedBuffer.data(), &len, buffer.data(), static_cast<int>(bytesRead))) {
            throw std::runtime_error("[ERROR] Decryption update failed");
        }

        // Write the decrypted chunk
        if (len > 0) {
            outputFile.write(reinterpret_cast<const char*>(decryptedBuffer.data()), len);
        }

        totalRead += bytesRead;
        ciphertextSize -= bytesRead;
        showProgress(totalRead, fileSize - headerSize, "Decryption");
    }

    // Read authentication tag (the last TAG_SIZE bytes of the file)
    std::vector<unsigned char> tag(TAG_SIZE);
    inputFile.read(reinterpret_cast<char*>(tag.data()), TAG_SIZE);
    if (inputFile.gcount() != TAG_SIZE) {
        throw std::runtime_error("[ERROR] Invalid authentication tag: expected " +
            std::to_string(TAG_SIZE) + " bytes, got " +
            std::to_string(inputFile.gcount()));
    }

    // Set tag for verification
    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data())) {
        throw std::runtime_error("[ERROR] Failed to set authentication tag");
    }

    // Finalize decryption and verify tag
    int finalLen;
    if (!EVP_CipherFinal_ex(ctx.get(), decryptedBuffer.data(), &finalLen)) {
        throw std::runtime_error("[ERROR] Decryption failed. Wrong password or tampered file.");
    }

    // Write any remaining decrypted data
    if (finalLen > 0) {
        outputFile.write(reinterpret_cast<const char*>(decryptedBuffer.data()), finalLen);
    }

    // The tag has verified, so the plaintext is authentic and an empty result is a
    // legitimately empty file rather than a failed decryption.
    const std::uintmax_t decryptedSize = output.commit();

    std::cout << "\n[DONE] Decryption successful!\n[DONE] File saved as: " << outputFilename
        << " (" << decryptedSize << " bytes)" << std::endl;
}

static void showHeader() {
    std::cout << "\033[2J\033[H" << std::flush;
    std::cout << "AES-256-GCM File Encryption/Decryption Tool" << std::endl;
    std::cout << "===========================================" << std::endl;
    std::cout << std::endl;
}

static unsigned int showMenu() {
    showHeader();
    std::cout << "1. Generate password key" << std::endl;
    std::cout << "2. Encrypt/Decrypt a file" << std::endl;
    std::cout << "0. Exit" << std::endl;
    std::cout << std::endl;

    std::string input = getInput("Choose option: ");
    try {
        return std::stoi(input);
    }
    catch (const std::exception&) {
        return 99;
    }
}

// fileExists only accepts regular files, so a rejected path is either missing or a
// directory; say which, because "File not found" on a folder is misleading.
static void reportUnusableInput(const std::string& filename) {
    std::error_code ec;
    if (std::filesystem::is_directory(filename, ec)) {
        std::cout << "Not a regular file: " << filename << std::endl;
    }
    else {
        std::cout << "File not found: " << filename << std::endl;
    }
}

static void processFile(const std::string& filename) {
    const bool encrypt = !isEncryptedFile(filename);

    // A file whose header already reads as encrypted should not be encrypted a second
    // time just because it was renamed. Encryption is not reversible on its own, so
    // doing it anyway quietly buries the original.
    if (encrypt && isValidEncryptedFile(filename)) {
        std::cout << "This file is already encrypted but does not end in .enc." << std::endl;
        std::cout << "Rename it to end in .enc and run this again to decrypt it." << std::endl;
        return;
    }

    std::string operation = encrypt ? "Encryption" : "Decryption";
    std::string outputFilename = getOutputFilename(filename, encrypt);

    showHeader();
    std::cout << "=> [INPUT FILE]: " << filename << std::endl;
    std::cout << "=> [OPERATION]: " << operation << std::endl;
    std::cout << "=> [OUTPUT FILE]: " << outputFilename << std::endl;
    std::cout << std::endl;

    if (!askOverwrite(outputFilename)) {
        std::cout << "=> Operation cancelled." << std::endl;
        return;
    }

    std::string passwordSource = getInput("=> Use (p)assword or (k)ey file? [p/k]: ");
    passwordSource = toLower(passwordSource);

    SecureString password;

    if (passwordSource == "p" || passwordSource == "password") {
        if (!getPassword(operation, password)) {
            std::cout << "=> Operation cancelled." << std::endl;
            return;
        }
    }
    else if (passwordSource == "k" || passwordSource == "key") {
        try {
            std::string key = readKey("password.key");
            password.assign(key);
            OPENSSL_cleanse(key.data(), key.size());
        }
        catch (const std::exception& e) {
            std::cout << "Error reading key file: " << e.what() << std::endl;
            std::cout << "Please generate a key first or use password mode." << std::endl;
            return;
        }
    }
    else {
        std::cout << "Invalid choice. Using password mode." << std::endl;
        if (!getPassword(operation, password)) {
            std::cout << "=> Operation cancelled." << std::endl;
            return;
        }
    }

    if (password.empty()) {
        std::cout << "Password is empty. Operation cancelled." << std::endl;
        return;
    }

    try {
        if (encrypt) {
            aesEncryptFile(filename, outputFilename, password);
        }
        else {
            aesDecryptFile(filename, outputFilename, password);
        }
    }
    catch (const std::exception& e) {
        std::cout << "Error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    try {
        // If file is dropped on executable or provided as argument
        if (argc > 1) {
            std::string filename = argv[1];
            if (fileExists(filename)) {
                processFile(filename);
            }
            else {
                reportUnusableInput(filename);
            }

            std::cout << std::endl;
            std::string ignored;
            readInputLine(ignored, "Press Enter to exit...", false);
            return 0;
        }

        // Interactive mode
        unsigned int option = showMenu();

        while (option != 0 && !inputClosed()) {
            try {
                if (option == 1) {
                    showHeader();
                    std::string key = generateRandomPassword(64);
                    saveKey(key, "password.key");
                    OPENSSL_cleanse(key.data(), key.size());
                    std::cout << "Key saved to password.key" << std::endl;
                    std::cout << "Store this file securely!" << std::endl << std::endl;
                }
                else if (option == 2) {
                    showHeader();
                    std::string filename = getInput("Enter file path: ");
                    if (fileExists(filename)) {
                        processFile(filename);
                    }
                    else {
                        reportUnusableInput(filename);
                    }
                }
                else {
                    std::cout << "Invalid option." << std::endl;
                }
            }
            catch (const std::exception& ex) {
                std::cerr << "Error: " << ex.what() << std::endl;
            }

            std::cout << std::endl;
            std::string ignored;
            if (!readInputLine(ignored, "Press Enter to continue...", false)) {
                break;
            }
            option = showMenu();
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "Fatal Error: " << ex.what() << std::endl;
        return 1;
    }

    std::cout << "Goodbye!" << std::endl;
    return 0;
}