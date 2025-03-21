#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <memory>
#include <stdexcept>
#include <conio.h>
#include <cstring>

#include "EncDecUtils.h"

const int PBKDF2_ITERATIONS = 10000000; // 10 million
const int AES_KEYLEN = 32;
const int AES_IVLEN = 12;
const int SALT_SIZE = 16;
const int TAG_SIZE = 16;
const size_t BUFFER_SIZE = 4096;
uint8_t version = 1;

static void handleErrors(const std::string& msg) {
	std::cerr << "Error: " << msg << std::endl;
}

static std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt) {
	std::vector<unsigned char> key(AES_KEYLEN);
	if (!PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.length()), salt.data(), static_cast<int>(salt.size()), PBKDF2_ITERATIONS, EVP_sha256(), static_cast<int>(key.size()), key.data())) {
		throw std::runtime_error("Key derivation failed");
	}
	return key;
}

static std::string getPassword() {
	std::string password;
	std::cout << "Enter password for Enc/Dec: ";
	char ch;
	while ((ch = _getch()) != '\r') {
		if (ch == 8 && !password.empty()) {
			password.pop_back();
			std::cout << "\b \b";
		}
		else if (ch != 8) {
			password.push_back(ch);
			std::cout << '*';
		}
	}
	std::cout << std::endl;
	return password;
}

static std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> createCipherContext(const EVP_CIPHER* cipher, const unsigned char* key, const unsigned char* iv, int encrypt) {
	std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!ctx || !EVP_CipherInit_ex(ctx.get(), cipher, nullptr, key, iv, encrypt)) {
		throw std::runtime_error("Cipher context initialization failed");
	}
	return ctx;
}

static void aesEncryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::string& password) {
	std::ifstream inputFile(inputFilename, std::ios::binary);
	if (!inputFile) throw std::runtime_error("Could not open input file");

	std::ofstream outputFile(outputFilename, std::ios::binary);
	if (!outputFile) throw std::runtime_error("Could not open output file");

	outputFile.write(reinterpret_cast<const char*>(&version), sizeof(version));

	std::vector<unsigned char> salt(SALT_SIZE);
	std::vector<unsigned char> iv(AES_IVLEN);
	if (!RAND_bytes(salt.data(), SALT_SIZE) || !RAND_bytes(iv.data(), AES_IVLEN)) {
		throw std::runtime_error("Random number generation failed");
	}

	outputFile.write(reinterpret_cast<const char*>(salt.data()), SALT_SIZE);
	outputFile.write(reinterpret_cast<const char*>(iv.data()), AES_IVLEN);

	std::vector<unsigned char> key = deriveKey(password, salt);
	OPENSSL_cleanse(const_cast<char*>(password.data()), password.length());
	auto ctx = createCipherContext(EVP_aes_256_gcm(), key.data(), iv.data(), 1);

	std::vector<unsigned char> buffer(BUFFER_SIZE);
	std::vector<unsigned char> encryptedBuffer(BUFFER_SIZE + TAG_SIZE);
	int len;

	while (inputFile) {
		inputFile.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE);
		std::streamsize bytesRead = inputFile.gcount();
		if (bytesRead > 0) {
			if (!EVP_CipherUpdate(ctx.get(), encryptedBuffer.data(), &len, buffer.data(), static_cast<int>(bytesRead))) {
				throw std::runtime_error("Encryption update failed");
			}
			outputFile.write(reinterpret_cast<const char*>(encryptedBuffer.data()), len);
		}
	}

	if (!EVP_CipherFinal_ex(ctx.get(), encryptedBuffer.data(), &len)) {
		throw std::runtime_error("Encryption finalization failed");
	}
	outputFile.write(reinterpret_cast<const char*>(encryptedBuffer.data()), len);

	unsigned char tag[TAG_SIZE];
	if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag)) {
		throw std::runtime_error("Failed to get authentication tag");
	}
	outputFile.write(reinterpret_cast<const char*>(tag), TAG_SIZE);
	outputFile.flush();

	OPENSSL_cleanse(key.data(), key.size());
	OPENSSL_cleanse(buffer.data(), buffer.size());

	system("cls");
	std::cout << std::endl;
	std::cout << "Encryption successful!" << std::endl;
}

static void aesDecryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::string& password) {
	std::ifstream inputFile(inputFilename, std::ios::binary | std::ios::ate);
	if (!inputFile) throw std::runtime_error("Could not open input file");

	std::streamsize fileSize = inputFile.tellg();
	inputFile.seekg(0, std::ios::beg);

	if (fileSize < sizeof(uint8_t) + SALT_SIZE + AES_IVLEN + TAG_SIZE) {
		throw std::runtime_error("Invalid or corrupted encrypted file");
	}

	inputFile.read(reinterpret_cast<char*>(&version), sizeof(version));
	if (version != 1) {
		throw std::runtime_error("Unsupported encryption version");
	}

	std::vector<unsigned char> salt(SALT_SIZE);
	std::vector<unsigned char> iv(AES_IVLEN);
	std::vector<unsigned char> tag(TAG_SIZE);

	inputFile.read(reinterpret_cast<char*>(salt.data()), SALT_SIZE);
	inputFile.read(reinterpret_cast<char*>(iv.data()), AES_IVLEN);

	std::vector<unsigned char> key = deriveKey(password, salt);
	OPENSSL_cleanse(const_cast<char*>(password.data()), password.length());
	auto ctx = createCipherContext(EVP_aes_256_gcm(), key.data(), iv.data(), 0);

	std::streamsize ciphertextSize = fileSize - (sizeof(version) + SALT_SIZE + AES_IVLEN + TAG_SIZE);
	std::vector<unsigned char> decryptedData;
	decryptedData.reserve(ciphertextSize);

	std::vector<unsigned char> buffer(BUFFER_SIZE);
	std::vector<unsigned char> decryptedBuffer(BUFFER_SIZE);
	int len;

	while (ciphertextSize > 0) {
		std::streamsize readSize = std::min(ciphertextSize, (std::streamsize)BUFFER_SIZE);
		inputFile.read(reinterpret_cast<char*>(buffer.data()), readSize);
		std::streamsize bytesRead = inputFile.gcount();
		if (bytesRead > 0) {
			if (!EVP_CipherUpdate(ctx.get(), decryptedBuffer.data(), &len, buffer.data(), static_cast<int>(bytesRead))) {
				throw std::runtime_error("Decryption update failed");
			}
			decryptedData.insert(decryptedData.end(), decryptedBuffer.begin(), decryptedBuffer.begin() + len);
		}
		ciphertextSize -= bytesRead;
	}

	inputFile.read(reinterpret_cast<char*>(tag.data()), TAG_SIZE);
	if (inputFile.gcount() != TAG_SIZE) {
		throw std::runtime_error("Invalid authentication tag size");
	}

	if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data())) {
		throw std::runtime_error("Failed to set authentication tag");
	}

	if (!EVP_CipherFinal_ex(ctx.get(), decryptedBuffer.data(), &len)) {
		throw std::runtime_error("Decryption failed. Possible wrong password or tampered file.");
	}

	std::ofstream outputFile(outputFilename, std::ios::binary);
	if (!outputFile) throw std::runtime_error("Could not open output file");

	outputFile.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());
	outputFile.write(reinterpret_cast<const char*>(decryptedBuffer.data()), len);
	outputFile.flush();

	OPENSSL_cleanse(key.data(), key.size());
	OPENSSL_cleanse(buffer.data(), buffer.size());

	system("cls");
	std::cout << std::endl;
	std::cout << "Decryption successful!" << std::endl;
}

static std::string getInput(const std::string& prompt) {
	std::string input;
	std::cout << prompt;
	std::getline(std::cin, input);
	return input;
}

static std::string validateDecryptionFile(const std::string& filename) {
	if (filename.size() > 4 && filename.substr(filename.size() - 4) == ".enc") {
		return filename.substr(0, filename.size() - 4);  // Remove .enc extension
	}
	std::cout << "\nInvalid file for decryption.\nEncrypted file must end in .enc.\n";
	return "";
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
	std::cout << "Enter your option: ";
	std::cin >> option;
	std::cin.ignore();

	return option;
}

int main(int argc, char* argv[]) {
	std::string filename, mode, selection, password;
	int option = (argc > 1) ? 2 : chooseOption();

	while (option != 0) {
		try {
			if (option == 1) {
				std::string key = generateRandomPassword(64);
				saveKey(key);

				system("cls");
				std::cout << std::endl;
				std::cout << "\nKey saved to password.key file\n"
					<< "Store this file safely!\n"
					<< "If lost, all data is inaccessible!\n\n";
			}
			else if (option == 2) {
				system("cls");
				std::cout << std::endl;

				filename = (argc > 1) ? argv[1] : getInput("Enter filepath or filename: ");
				mode = getInput("Encrypt (e) or Decrypt (d) file?: ");
				if (mode != "e" && mode != "d") { option = 99; continue; };

				selection = getInput("Enter password (p) or Use password.key (u): ");
				if (selection != "p" && selection != "u") { option = 99; continue; };
				password = (selection == "p") ? getPassword() : readKey();
				if (password.empty()) {
					std::cout << std::endl;
					std::cout << "Password is empty. Cannot perform operation" << std::endl;
					argc = 1;
				}
				else {
					std::string outFilename = (mode == "e") ? filename + ".enc" : [&]() { return validateDecryptionFile(filename); }();
					if (outFilename.empty()) {
						std::cout << std::endl;
						std::cout << "Input file is empty. Cannot perform operation" << std::endl;
						argc = 1;
					};

					if (std::ifstream(outFilename) && getInput("Output file exists. Overwrite? (y/n): ") != "y") continue;

					(mode == "e") ? aesEncryptFile(filename, outFilename, password) : aesDecryptFile(filename, outFilename, password);
					std::cout << "Operation successfully performed.\n";
				}
			}
			else if (option == 9) {
				option = chooseOption();
				continue;
			}
			else {
				std::cout << "\nInvalid option selected.";
			}
		}
		catch (const std::exception& ex) {
			std::cerr << "\nOperation Error: " << ex.what() << std::endl;
		}

		option = std::stoi(getInput("\nEnter 9 to return / 0 to exit: "));
		argc = 1;
	}

	std::cout << "Exiting program.\n";
	return 0;
}