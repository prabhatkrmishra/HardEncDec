#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <memory>
#include <stdexcept>
#include <conio.h>
#include <cstdio>
#include <cstring>
#include <sstream>

#include "EncDecUtils.h"
#include <ranges>
#include <algorithm>

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
        return data.size() - 1;
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

static std::vector<unsigned char> deriveKey(const SecureString& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(AES_KEYLEN);

    if (!PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
        salt.data(), static_cast<int>(salt.size()),
        PBKDF2_ITERATIONS, EVP_sha256(),
        static_cast<int>(key.size()), key.data())) {
        handleOpenSSLError("Key derivation");
    }
    return key;
}

static SecureString getPassword(const std::string& operation) {
    SecureString password;
    std::string tempPassword;
    std::string confirmPassword;

    while (true) {
        std::cout << "=> Enter password for " << operation << ": ";
        tempPassword.clear();

        char ch;
        while ((ch = _getch()) != '\r') {
            if (ch == 8 && !tempPassword.empty()) { // Backspace
                tempPassword.pop_back();
                std::cout << "\b \b";
            }
            else if (ch != 8 && ch != '\r') {
                tempPassword.push_back(ch);
                std::cout << '*';
            }
        }
        std::cout << std::endl;

        if (tempPassword.empty()) {
            std::cout << "Password cannot be empty. Please try again." << std::endl;
            continue;
        }

        std::cout << "=> Confirm password for " << operation << ": ";
        confirmPassword.clear();

        while ((ch = _getch()) != '\r') {
            if (ch == 8 && !confirmPassword.empty()) { // Backspace
                confirmPassword.pop_back();
                std::cout << "\b \b";
            }
            else if (ch != 8 && ch != '\r') {
                confirmPassword.push_back(ch);
                std::cout << '*';
            }
        }
        std::cout << std::endl;

        if (tempPassword == confirmPassword) {
            break;
        }
        else {
            std::cout << "\n[INVALID] Passwords do not match. Please try again.\n" << std::endl;
        }
    }

    password.assign(tempPassword);

    // Cleanse temporary strings from memory
    OPENSSL_cleanse(const_cast<char*>(tempPassword.data()), tempPassword.size());
    OPENSSL_cleanse(const_cast<char*>(confirmPassword.data()), confirmPassword.size());

    return password;
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

static void aesEncryptFile(const std::string& inputFilename, const std::string& outputFilename, const SecureString& password) {
    if (!fileExists(inputFilename)) {
        throw std::runtime_error("[ERROR] Input file does not exist: " + inputFilename);
    }

    std::ifstream inputFile(inputFilename, std::ios::binary);
    if (!inputFile) {
        throw std::runtime_error("[ERROR] Could not open input file: " + inputFilename);
    }

    std::ofstream outputFile(outputFilename, std::ios::binary);
    if (!outputFile) {
        throw std::runtime_error("[ERROR] Could not open output file: " + outputFilename);
    }

    // Get file size for progress reporting
    inputFile.seekg(0, std::ios::end);
    std::streamsize fileSize = inputFile.tellg();
    inputFile.seekg(0, std::ios::beg);

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
    std::vector<unsigned char> key = deriveKey(password, salt);

    // Initialize encryption context
    auto ctx = createCipherContext(EVP_aes_256_gcm(), key.data(), iv.data(), 1);

    std::vector<unsigned char> buffer(BUFFER_SIZE);
    std::vector<unsigned char> encryptedBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
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

    if (!outputFile.good()) {
        throw std::runtime_error("[ERROR] Error writing to output file");
    }

    // Clean up sensitive data
    OPENSSL_cleanse(key.data(), key.size());
    OPENSSL_cleanse(buffer.data(), buffer.size());
    OPENSSL_cleanse(encryptedBuffer.data(), encryptedBuffer.size());

    std::cout << "\n[DONE] Encryption successful!\n[DONE] File saved as: " << outputFilename << std::endl;
}

// GCM authenticates only after the final block, so a wrong password or a tampered
// file leaves unauthenticated bytes on disk before the tag check runs. This removes
// the partial output on any failure rather than leaving a corrupt file behind.
class OutputFileGuard {
public:
    OutputFileGuard(const std::string& path, std::ofstream& stream)
        : path_(path), stream_(stream) {}

    ~OutputFileGuard() {
        if (!committed_) {
            stream_.close();
            std::remove(path_.c_str());
        }
    }

    void commit() { committed_ = true; }

    OutputFileGuard(const OutputFileGuard&) = delete;
    OutputFileGuard& operator=(const OutputFileGuard&) = delete;

private:
    const std::string& path_;
    std::ofstream& stream_;
    bool committed_ = false;
};

static void aesDecryptFile(const std::string& inputFilename, const std::string& outputFilename, const SecureString& password) {
    if (!isValidEncryptedFile(inputFilename)) {
        throw std::runtime_error("[ERROR] Invalid or corrupted encrypted file: " + inputFilename);
    }

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
        throw std::runtime_error("[ERROR] Unsupported file version: " + std::to_string(fileVersion) +
            " (expected " + std::to_string(FILE_VERSION) + ")");
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

    // Calculate ciphertext size (excluding header and tag)
    std::streamsize headerSize = sizeof(fileVersion) + SALT_SIZE + AES_IVLEN + TAG_SIZE;
    if (fileSize < headerSize) {
        throw std::runtime_error("[ERROR] File too small to be a valid encrypted file");
    }

    std::streamsize ciphertextSize = fileSize - headerSize;

    // Seek back to start of ciphertext
    inputFile.seekg(sizeof(fileVersion) + SALT_SIZE + AES_IVLEN, std::ios::beg);

    // Derive key from password
    std::vector<unsigned char> key = deriveKey(password, salt);

    // Initialize decryption context
    auto ctx = createCipherContext(EVP_aes_256_gcm(), key.data(), iv.data(), 0);

    std::ofstream outputFile(outputFilename, std::ios::binary);
    if (!outputFile) {
        throw std::runtime_error("[ERROR] Could not open output file: " + outputFilename);
    }
    OutputFileGuard outputGuard(outputFilename, outputFile);

    std::vector<unsigned char> buffer(BUFFER_SIZE);
    std::vector<unsigned char> decryptedBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
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

        // Check if we've read all ciphertext
        if (bytesRead < readSize) break;
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

    // Verify the output file was written correctly
    outputFile.flush();
    if (!outputFile.good()) {
        throw std::runtime_error("[ERROR] Error writing to output file");
    }
    outputFile.close();

    // Verify the decrypted file size is reasonable
    std::ifstream checkFile(outputFilename, std::ios::binary | std::ios::ate);
    std::streamsize decryptedSize = checkFile.tellg();
    checkFile.close();

    if (decryptedSize == 0) {
        throw std::runtime_error("[ERROR] Decrypted file is empty - decryption may have failed");
    }
    outputGuard.commit();

    // Clean up sensitive data
    OPENSSL_cleanse(key.data(), key.size());
    OPENSSL_cleanse(buffer.data(), buffer.size());
    OPENSSL_cleanse(decryptedBuffer.data(), decryptedBuffer.size());

    std::cout << "\n[DONE] Decryption successful!\n[DONE] File saved as: " << outputFilename
        << " (" << decryptedSize << " bytes)" << std::endl;
}

static void initializeOpenSSL() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

static void cleanupOpenSSL() {
    EVP_cleanup();
    ERR_free_strings();
}

static void showHeader() {
    system("cls");
    std::cout << std::endl;
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

static void processFile(const std::string& filename) {
    bool encrypt = !isEncryptedFile(filename);
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
        password = getPassword(operation);
    }
    else if (passwordSource == "k" || passwordSource == "key") {
        try {
            std::string key = readKey("password.key");
            password.assign(key);
            OPENSSL_cleanse(const_cast<char*>(key.data()), key.size());
        }
        catch (const std::exception& e) {
            std::cout << "Error reading key file: " << e.what() << std::endl;
            std::cout << "Please generate a key first or use password mode." << std::endl;
            return;
        }
    }
    else {
        std::cout << "Invalid choice. Using password mode." << std::endl;
        password = getPassword(operation);
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
    initializeOpenSSL();

    try {
        // If file is dropped on executable or provided as argument
        if (argc > 1) {
            std::string filename = argv[1];
            if (fileExists(filename)) {
                processFile(filename);
            }
            else {
                std::cout << "File not found: " << filename << std::endl;
            }

            std::cout << std::endl;
            std::string input = getInput("Press Enter to exit...");
            return 0;
        }

        // Interactive mode
        unsigned int option = showMenu();

        while (option != 0) {
            try {
                if (option == 1) {
                    showHeader();
                    std::string key = generateRandomPassword(64);
                    saveKey(key, "password.key");
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
                        std::cout << "File not found: " << filename << std::endl;
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
            std::string input = getInput("Press Enter to continue...");
            option = showMenu();
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "Fatal Error: " << ex.what() << std::endl;
        cleanupOpenSSL();
        return 1;
    }

    cleanupOpenSSL();
    std::cout << "Goodbye!" << std::endl;
    return 0;
}