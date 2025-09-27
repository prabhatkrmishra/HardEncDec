#pragma once

#ifndef ENCDEC_UTILS_H
#define ENCDEC_UTILS_H

#include <string>

// Encryption constants
const int PBKDF2_ITERATIONS = 10000000; // 10 million iterations
const int AES_KEYLEN = 32;
const int AES_IVLEN = 12;
const int SALT_SIZE = 16;
const int TAG_SIZE = 16;
const size_t BUFFER_SIZE = 8192;
const uint8_t FILE_VERSION = 2;

std::string generateRandomPassword(size_t length = 64);

void saveKey(const std::string& key, const std::string& filename = "password.key");
std::string readKey(const std::string& filename = "password.key");

bool fileExists(const std::string& filename);
bool isValidEncryptedFile(const std::string& filename);
static void analyzeEncryptedFile(const std::string& filename);

#endif
