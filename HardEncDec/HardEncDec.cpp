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

const int AES_KEYLEN = 32;
const int AES_IVLEN = 12;
const int SALT_SIZE = 16;
const int TAG_SIZE = 16;
const int PBKDF2_ITERATIONS = 200000;
const size_t BUFFER_SIZE = 4096;

static void handleErrors(const std::string& msg) {
	std::cerr << "Error: " << msg << std::endl;
}

std::vector<unsigned char> deriveKey(const std::string& password, const std::vector<unsigned char>& salt) {
	std::vector<unsigned char> key(AES_KEYLEN);
	if (!PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt.data(), salt.size(), PBKDF2_ITERATIONS, EVP_sha256(), key.size(), key.data())) {
		throw std::runtime_error("Key derivation failed");
	}
	return key;
}

static std::string getPassword() {
	std::string password;
	std::cout << "Enter password: ";
	char ch;
	while ((ch = _getch()) != '\r') {
		if (ch == '\b' && !password.empty()) {
			password.pop_back();
			std::cout << "\b \b";
		}
		else if (ch != '\b') {
			password.push_back(ch);
			std::cout << '*';
		}
	}
	std::cout << std::endl;
	return password;
}

std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> createCipherContext(const EVP_CIPHER* cipher, const unsigned char* key, const unsigned char* iv, int encrypt) {
	std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	if (!ctx || !EVP_CipherInit_ex(ctx.get(), cipher, nullptr, key, iv, encrypt)) {
		throw std::runtime_error("Cipher context initialization failed");
	}
	return ctx;
}

static void aesEncryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::string& password) {
	std::ifstream inputFile(inputFilename, std::ios::binary);
	std::ofstream outputFile(outputFilename, std::ios::binary);

	if (!inputFile) throw std::runtime_error("Could not open input file");
	if (!outputFile) throw std::runtime_error("Could not open output file");

	std::vector<unsigned char> salt(SALT_SIZE);
	RAND_bytes(salt.data(), SALT_SIZE);
	std::vector<unsigned char> key = deriveKey(password, salt);
	std::vector<unsigned char> iv(AES_IVLEN);
	RAND_bytes(iv.data(), AES_IVLEN);

	outputFile.write(reinterpret_cast<const char*>(salt.data()), SALT_SIZE);
	outputFile.write(reinterpret_cast<const char*>(iv.data()), AES_IVLEN);

	auto ctx = createCipherContext(EVP_aes_256_gcm(), key.data(), iv.data(), 1);

	std::vector<unsigned char> buffer(BUFFER_SIZE);
	std::vector<unsigned char> encryptedBuffer(BUFFER_SIZE + TAG_SIZE);
	int len, encryptedLen;

	while (inputFile.read(reinterpret_cast<char*>(buffer.data()), BUFFER_SIZE)) {
		if (!EVP_CipherUpdate(ctx.get(), encryptedBuffer.data(), &len, buffer.data(), inputFile.gcount())) {
			throw std::runtime_error("Encryption update failed");
		}
		outputFile.write(reinterpret_cast<const char*>(encryptedBuffer.data()), len);
	}

	if (!EVP_CipherFinal_ex(ctx.get(), encryptedBuffer.data(), &len)) {
		//if final fails, the tag is invalid.
		throw std::runtime_error("Encryption finalization failed");
	}
	encryptedLen = len;

	unsigned char tag[TAG_SIZE];
	if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag)) {
		throw std::runtime_error("Failed to get authentication tag");
	}
	outputFile.write(reinterpret_cast<const char*>(tag), TAG_SIZE);

	OPENSSL_cleanse(key.data(), key.size());
}

static void aesDecryptFile(const std::string& inputFilename, const std::string& outputFilename, const std::string& password) {
	std::ifstream inputFile(inputFilename, std::ios::binary | std::ios::ate);

	if (!inputFile) throw std::runtime_error("Could not open input file");

	std::streamsize fileSize = inputFile.tellg();
	if (fileSize < SALT_SIZE + AES_IVLEN + TAG_SIZE) {
		throw std::runtime_error("Invalid file format");
	}

	inputFile.seekg(0, std::ios::beg);

	std::vector<unsigned char> salt(SALT_SIZE);
	std::vector<unsigned char> iv(AES_IVLEN);
	std::vector<unsigned char> tag(TAG_SIZE);

	inputFile.read(reinterpret_cast<char*>(salt.data()), SALT_SIZE);
	inputFile.read(reinterpret_cast<char*>(iv.data()), AES_IVLEN);

	std::vector<unsigned char> key = deriveKey(password, salt);

	auto ctx = createCipherContext(EVP_aes_256_gcm(), key.data(), iv.data(), 0);

	// Calculate ciphertext size
	std::streamsize ciphertextSize = fileSize - SALT_SIZE - AES_IVLEN - TAG_SIZE;

	// Store decrypted chunks in a vector
	std::vector<unsigned char> decryptedData;
	// Reserve space to avoid reallocations
	decryptedData.reserve(ciphertextSize); 

	std::vector<unsigned char> buffer(BUFFER_SIZE);
	std::vector<unsigned char> decryptedBuffer(BUFFER_SIZE);
	int len;

	while (ciphertextSize > 0) {
		std::streamsize readSize = std::min(ciphertextSize, (std::streamsize)BUFFER_SIZE);
		inputFile.read(reinterpret_cast<char*>(buffer.data()), readSize);

		if (!EVP_CipherUpdate(ctx.get(), decryptedBuffer.data(), &len, buffer.data(), readSize)) {
			throw std::runtime_error("Decryption update failed");
		}

		decryptedData.insert(decryptedData.end(), decryptedBuffer.begin(), decryptedBuffer.begin() + len);
		ciphertextSize -= readSize;
	}

	inputFile.read(reinterpret_cast<char*>(tag.data()), TAG_SIZE);

	if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data())) {
		throw std::runtime_error("Failed to set authentication tag");
	}

	int decryptedLen = 0;
	if (!EVP_CipherFinal_ex(ctx.get(), nullptr, &decryptedLen)) {
		throw std::runtime_error("Decryption finalization failed. Incorrect password or data tampered.");
	}

	std::ofstream outputFile(outputFilename, std::ios::binary);
	if (!outputFile) throw std::runtime_error("Could not open output file");

	outputFile.write(reinterpret_cast<const char*>(decryptedData.data()), decryptedData.size());

	OPENSSL_cleanse(key.data(), key.size());
}

int main(int argc, char* argv[]) {
	std::string filename, mode;

	if (argc > 1) {
		filename = argv[1];
	}
	else {
		std::cout << "Enter filepath or flename: ";
		std::getline(std::cin, filename);
	}

	std::cout << "Encrypt(e) or Decrypt(d)? (e/d): ";
	std::getline(std::cin, mode);

	std::string password = getPassword();

	try {
		std::string outFilename;
		if (mode == "e") {
			outFilename = filename + ".enc";
		}
		else if (mode == "d") {
			if (filename.length() > 4 && filename.substr(filename.length() - 4) == ".enc") {
				outFilename = filename.substr(0, filename.length() - 4);
			}
			else {
				throw std::runtime_error("Encrypted file must end in .enc");
			}
		}
		else {
			throw std::runtime_error("Invalid mode. Use 'e' or 'd'.");
		}

		if (std::ifstream(outFilename)) {
			std::cerr << "Output file already exists. Overwrite? (y/n): ";
			char response;
			std::cin >> response;
			if (response != 'y') return 1;
			std::cin.ignore();
		}

		if (mode == "e") {
			aesEncryptFile(filename, outFilename, password);
		}
		else if (mode == "d") {
			aesDecryptFile(filename, outFilename, password);
		}
		else {
			throw std::runtime_error("Invalid mode. Use 'e' or 'd'.");
		}

		std::cout << "Operation successful!" << std::endl;
	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
		return 1;
	}

	return 0;
}