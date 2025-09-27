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
#include <cstring>
#include <sstream>

#include "EncDecUtils.h"

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

static SecureString getPassword() {
    SecureString password;
    std::string tempPassword;

    std::cout << "Enter password for Enc/Dec: ";
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

    password.assign(tempPassword);
    OPENSSL_cleanse(const_cast<char*>(tempPassword.data()), tempPassword.size());

    return password;
}

static std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
createCipherContext(const EVP_CIPHER* cipher, const unsigned char* key,
    const unsigned char* iv, int encrypt) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (!EVP_CipherInit_ex(ctx.get(), cipher, nullptr, key, iv, encrypt)) {
        handleOpenSSLError("Cipher initialization");
    }

    return ctx;
}

static void showProgress(std::streamsize current, std::streamsize total, const std::string& operation) {
    if (total > 0) {
        int percentage = static_cast<int>((current * 100) / total);
        std::cout << "\r" << operation << " Progress: " << percentage << "% ("
            << current << "/" << total << " bytes)";
        std::cout.flush();
    }
}

static void aesEncryptFile(const std::string& inputFilename, const std::string& outputFilename, const SecureString& password) {
    if (!fileExists(inputFilename)) {
        throw std::runtime_error("Input file does not exist: " + inputFilename);
    }

    std::ifstream inputFile(inputFilename, std::ios::binary);
    if (!inputFile) {
        throw std::runtime_error("Could not open input file: " + inputFilename);
    }

    std::ofstream outputFile(outputFilename, std::ios::binary);
    if (!outputFile) {
        throw std::runtime_error("Could not open output file: " + outputFilename);
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
        throw std::runtime_error("Random number generation failed");
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
    while (inputFile.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE) || inputFile.gcount() > 0) {
        std::streamsize bytesRead = inputFile.gcount();
        totalRead += bytesRead;

        if (!EVP_CipherUpdate(ctx.get(), encryptedBuffer.data(), &len, buffer.data(), static_cast<int>(bytesRead))) {
            throw std::runtime_error("Encryption update failed");
        }
        outputFile.write(reinterpret_cast<const char*>(encryptedBuffer.data()), len);

        showProgress(totalRead, fileSize, "Encryption");
    }

    // Finalize encryption
    if (!EVP_CipherFinal_ex(ctx.get(), encryptedBuffer.data(), &len)) {
        throw std::runtime_error("Encryption finalization failed");
    }
    outputFile.write(reinterpret_cast<const char*>(encryptedBuffer.data()), len);

    // Get and write authentication tag
    unsigned char tag[TAG_SIZE];
    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag)) {
        throw std::runtime_error("Failed to get authentication tag");
    }
    outputFile.write(reinterpret_cast<const char*>(tag), TAG_SIZE);

    if (!outputFile.good()) {
        throw std::runtime_error("Error writing to output file");
    }

    // Clean up sensitive data
    OPENSSL_cleanse(key.data(), key.size());
    OPENSSL_cleanse(buffer.data(), buffer.size());
    OPENSSL_cleanse(encryptedBuffer.data(), encryptedBuffer.size());

    std::cout << "\nEncryption successful! File saved as: " << outputFilename << std::endl;
}

static void aesDecryptFile(const std::string& inputFilename, const std::string& outputFilename, const SecureString& password) {
    if (!isValidEncryptedFile(inputFilename)) {
        throw std::runtime_error("Invalid or corrupted encrypted file: " + inputFilename);
    }

    std::ifstream inputFile(inputFilename, std::ios::binary);
    if (!inputFile) {
        throw std::runtime_error("Could not open input file: " + inputFilename);
    }

    // Read and validate version
    uint8_t fileVersion;
    inputFile.read(reinterpret_cast<char*>(&fileVersion), sizeof(fileVersion));
    if (!inputFile) {
        throw std::runtime_error("Failed to read file version");
    }

    // Support both version 1 and 2 for backward compatibility
    if (fileVersion != 1 && fileVersion != FILE_VERSION) {
        throw std::runtime_error("Unsupported file version: " + std::to_string(fileVersion) +
            " (expected 1 or " + std::to_string(FILE_VERSION) + ")");
    }

    // Read salt
    std::vector<unsigned char> salt(SALT_SIZE);
    inputFile.read(reinterpret_cast<char*>(salt.data()), SALT_SIZE);
    if (inputFile.gcount() != SALT_SIZE) {
        throw std::runtime_error("Failed to read salt: expected " +
            std::to_string(SALT_SIZE) + " bytes, got " +
            std::to_string(inputFile.gcount()));
    }

    // Read IV
    std::vector<unsigned char> iv(AES_IVLEN);
    inputFile.read(reinterpret_cast<char*>(iv.data()), AES_IVLEN);
    if (inputFile.gcount() != AES_IVLEN) {
        throw std::runtime_error("Failed to read IV: expected " +
            std::to_string(AES_IVLEN) + " bytes, got " +
            std::to_string(inputFile.gcount()));
    }

    // Get file size
    inputFile.seekg(0, std::ios::end);
    std::streamsize fileSize = inputFile.tellg();

    // Calculate ciphertext size (excluding header and tag)
    std::streamsize headerSize = sizeof(fileVersion) + SALT_SIZE + AES_IVLEN + TAG_SIZE;
    if (fileSize < headerSize) {
        throw std::runtime_error("File too small to be a valid encrypted file");
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
        throw std::runtime_error("Could not open output file: " + outputFilename);
    }

    std::vector<unsigned char> buffer(BUFFER_SIZE);
    std::vector<unsigned char> decryptedBuffer(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    std::streamsize totalRead = 0;
    int len;

    // Read and decrypt file data in chunks
    while (ciphertextSize > 0) {
        std::streamsize readSize = std::min(ciphertextSize, static_cast<std::streamsize>(BUFFER_SIZE));
        inputFile.read(reinterpret_cast<char*>(buffer.data()), readSize);
        std::streamsize bytesRead = inputFile.gcount();

        if (bytesRead <= 0) break;

        // Decrypt the chunk
        if (!EVP_CipherUpdate(ctx.get(), decryptedBuffer.data(), &len, buffer.data(), static_cast<int>(bytesRead))) {
            throw std::runtime_error("Decryption update failed");
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
        throw std::runtime_error("Invalid authentication tag: expected " +
            std::to_string(TAG_SIZE) + " bytes, got " +
            std::to_string(inputFile.gcount()));
    }

    // Set tag for verification
    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data())) {
        throw std::runtime_error("Failed to set authentication tag");
    }

    // Finalize decryption and verify tag
    int finalLen;
    if (!EVP_CipherFinal_ex(ctx.get(), decryptedBuffer.data(), &finalLen)) {
        throw std::runtime_error("Decryption failed. Wrong password or tampered file.");
    }

    // Write any remaining decrypted data
    if (finalLen > 0) {
        outputFile.write(reinterpret_cast<const char*>(decryptedBuffer.data()), finalLen);
    }

    // Verify the output file was written correctly
    outputFile.flush();
    if (!outputFile.good()) {
        throw std::runtime_error("Error writing to output file");
    }
    outputFile.close();

    // Verify the decrypted file size is reasonable
    std::ifstream checkFile(outputFilename, std::ios::binary | std::ios::ate);
    std::streamsize decryptedSize = checkFile.tellg();
    checkFile.close();

    if (decryptedSize == 0) {
        throw std::runtime_error("Decrypted file is empty - decryption may have failed");
    }

    // Clean up sensitive data
    OPENSSL_cleanse(key.data(), key.size());
    OPENSSL_cleanse(buffer.data(), buffer.size());
    OPENSSL_cleanse(decryptedBuffer.data(), decryptedBuffer.size());

    std::cout << "\nDecryption successful! File saved as: " << outputFilename
        << " (" << decryptedSize << " bytes)" << std::endl;
}

static std::string getInput(const std::string& prompt) {
    std::string input;
    std::cout << prompt;
    std::getline(std::cin, input);
    return input;
}

static std::string validateDecryptionFile(const std::string& filename) {
    if (filename.size() > 4 && filename.substr(filename.size() - 4) == ".enc") {
        return filename.substr(0, filename.size() - 4);
    }
    throw std::runtime_error("Invalid file for decryption. Encrypted file must end in .enc");
}

static bool askOverwrite(const std::string& filename) {
    if (fileExists(filename)) {
        std::string response = getInput("Output file exists. Overwrite? (y/n): ");
        return (response == "y" || response == "Y");
    }
    return true;
}

static unsigned int chooseOption() {
    unsigned int option = 99;

    system("cls");
    std::cout << std::endl;
    std::cout << "AES-256-GCM Encryption/Decryption Program with PBKDF2" << std::endl;
    std::cout << std::endl;
    std::cout << "=====================================================" << std::endl;
    std::cout << "1. Generate a 64 character password key" << std::endl;
    std::cout << "2. Encrypt or Decrypt a file" << std::endl;
    std::cout << "0. Exit Program" << std::endl;
    std::cout << "=====================================================" << std::endl;
    std::cout << std::endl;

    std::string input = getInput("Enter your option: ");
    try {
        option = std::stoi(input);
    }
    catch (const std::exception&) {
        option = 99;
    }

    return option;
}

static void initializeOpenSSL() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

static void cleanupOpenSSL() {
    EVP_cleanup();
    ERR_free_strings();
}

int main(int argc, char* argv[]) {
    initializeOpenSSL();

    try {
        unsigned int option = (argc > 1) ? 2 : chooseOption();

        while (option != 0) {
            try {
                if (option == 1) {
                    std::string key = generateRandomPassword(64);
                    saveKey(key, "password.key");

                    system("cls");
                    std::cout << std::endl;
                    std::cout << "Key saved to password.key file" << std::endl;
                    std::cout << "Store this file safely!" << std::endl;
                    std::cout << "If lost, all data is inaccessible!" << std::endl << std::endl;
                }
                else if (option == 2) {
                    std::string filename, mode, passwordSource;

                    if (argc > 1) {
                        if (argc > 1) filename = argv[1];
                        if (argc > 2) mode = argv[2];
                        if (argc > 3) passwordSource = argv[3];
                    }
                    else {
                        system("cls");
                        std::cout << std::endl;
                        filename = getInput("Enter filepath or filename: ");
                        mode = getInput("Encrypt (e) or Decrypt (d) file?: ");
                        passwordSource = getInput("Enter password (p) or Use password.key (u): ");
                    }

                    if (mode != "e" && mode != "d") {
                        std::cout << "Invalid mode. Use 'e' for encrypt or 'd' for decrypt." << std::endl;
                    }
                    else if (passwordSource != "p" && passwordSource != "u") {
                        std::cout << "Invalid password source. Use 'p' for password or 'u' for key file." << std::endl;
                    }
                    else {
                        SecureString password;

                        if (passwordSource == "p") {
                            password = getPassword();
                        }
                        else {
                            std::string key = readKey("password.key");
                            password.assign(key);
                            OPENSSL_cleanse(const_cast<char*>(key.data()), key.size());
                        }

                        if (password.empty()) {
                            std::cout << "Password is empty. Cannot perform operation." << std::endl;
                        }
                        else {
                            std::string outFilename;

                            if (mode == "e") {
                                outFilename = filename + ".enc";
                                if (!askOverwrite(outFilename)) {
                                    std::cout << "Operation cancelled." << std::endl;
                                }
                                else {
                                    aesEncryptFile(filename, outFilename, password);
                                }
                            }
                            else {
                                try {
                                    outFilename = validateDecryptionFile(filename);
                                    if (!askOverwrite(outFilename)) {
                                        std::cout << "Operation cancelled." << std::endl;
                                    }
                                    else {
                                        aesDecryptFile(filename, outFilename, password);
                                    }
                                }
                                catch (const std::exception& e) {
                                    std::cout << e.what() << std::endl;
                                }
                            }
                        }
                    }
                }
                else {
                    std::cout << "Invalid option selected." << std::endl;
                }
            }
            catch (const std::exception& ex) {
                std::cerr << "Operation Error: " << ex.what() << std::endl;
            }

            // Reset command line args after first use
            argc = 1;

            std::string input = getInput("\nEnter 9 for menu, 0 to exit: ");
            try {
                option = std::stoi(input);
                if (option == 9) {
                    option = chooseOption();
                }
            }
            catch (const std::exception&) {
                option = 0;
            }
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "Fatal Error: " << ex.what() << std::endl;
        cleanupOpenSSL();
        return 1;
    }

    cleanupOpenSSL();
    std::cout << "Exiting program." << std::endl;
    return 0;
}