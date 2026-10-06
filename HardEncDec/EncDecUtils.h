#pragma once

#ifndef ENCDEC_UTILS_H
#define ENCDEC_UTILS_H

#include <cstdint>
#include <iosfwd>
#include <string>

// Encryption constants
const int PBKDF2_ITERATIONS = 100000000; // 100 million iterations
const int AES_KEYLEN = 32;
const int AES_IVLEN = 12;
const int SALT_SIZE = 16;
const int TAG_SIZE = 16;
const size_t BUFFER_SIZE = 512 * 1024; // 512KB
// Only files written with this exact version can be decrypted. Bump this only for
// an incompatible format change; earlier files stay unreadable afterwards.
const uint8_t FILE_VERSION = 3;

std::string generateRandomPassword(size_t length = 64);

void saveKey(const std::string& key, const std::string& filename = "password.key");
std::string readKey(const std::string& filename = "password.key");

bool fileExists(const std::string& filename);
bool askOverwrite(const std::string& filename);
bool isValidEncryptedFile(const std::string& filename);
void explainUnsupportedVersion(int version);
bool isEncryptedFile(const std::string& filename);

std::string getOutputFilename(const std::string& inputFilename, bool encrypt);
std::string getInput(const std::string& prompt);
bool readInputLine(std::string& out, const std::string& prompt, bool masked);
bool inputClosed();
std::string toLower(const std::string& str);

void showProgress(std::streamsize current, std::streamsize total, const std::string& operation);

#endif
