#pragma once

#ifndef ENCDEC_UTILS_H
#define ENCDEC_UTILS_H

#include <string>

std::string generateRandomPassword(size_t length = 64);

void saveKey(const std::string& key, const std::string& filename = "password.key");
std::string readKey(const std::string& filename = "password.key");

#endif
