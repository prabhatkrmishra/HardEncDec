#include <random>
#include <fstream>
#include <stdexcept>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "EncDecUtils.h"

std::string generateRandomPassword(size_t length) {
    static const std::string allowedChars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~";

    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, static_cast<int>(allowedChars.size() - 1));

    std::string password;
    password.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        password.push_back(allowedChars[distribution(generator)]);
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
}

std::string readKey(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) {
        throw std::runtime_error("Cannot open file for reading: " + filename);
    }

    std::string key;
    std::getline(in, key);
    in.close();

    if (key.empty()) {
        throw std::runtime_error("Key file is empty: " + filename);
    }

    return key;
}

bool fileExists(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

bool isValidEncryptedFile(const std::string& filename) {
    if (!fileExists(filename)) return false;

    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) return false;

    std::streamsize size = file.tellg();
    file.close();

    // Check if file has minimum required size: version + salt + iv + tag
    const std::streamsize MIN_ENCRYPTED_SIZE = sizeof(uint8_t) + SALT_SIZE + AES_IVLEN + TAG_SIZE;
    if (size < MIN_ENCRYPTED_SIZE) {
        std::cerr << "File too small: " << size << " bytes (minimum " << MIN_ENCRYPTED_SIZE << " bytes required)" << std::endl;
        return false;
    }

    // Additional check: read version byte
    file.open(filename, std::ios::binary);
    if (!file) return false;

    uint8_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    file.close();

    // Support both version 1 and 2
    if (version != 1 && version != FILE_VERSION) {
        std::cerr << "Unsupported file version: " << static_cast<int>(version)
            << " (supported: 1, " << static_cast<int>(FILE_VERSION) << ")" << std::endl;
        return false;
    }

    return true;
}

static void analyzeEncryptedFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cout << "Cannot open file for analysis: " << filename << std::endl;
        return;
    }

    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    uint8_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));

    std::cout << "File Analysis:" << std::endl;
    std::cout << "Total size: " << size << " bytes" << std::endl;
    std::cout << "Version: " << static_cast<int>(version) << std::endl;
    std::cout << "Expected header size: " << (sizeof(version) + SALT_SIZE + AES_IVLEN + TAG_SIZE) << " bytes" << std::endl;
    std::cout << "Expected data size: " << (size - (sizeof(version) + SALT_SIZE + AES_IVLEN + TAG_SIZE)) << " bytes" << std::endl;

    file.close();
}