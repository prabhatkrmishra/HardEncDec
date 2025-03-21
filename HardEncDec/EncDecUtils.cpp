#include <random>
#include <fstream>
#include <stdexcept>
#include <iostream>

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
    out.close();
}

std::string readKey(const std::string& filename) {
    std::ifstream in(filename, std::ios::binary);
    if (!in) {
        system("cls");
        std::cout << "Cannot open file for reading: " + filename << std::endl;
    }
    std::string key;
    std::getline(in, key);
    in.close();
    return key;
}