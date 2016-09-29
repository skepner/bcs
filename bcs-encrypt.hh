#pragma once
#include <string>

// ----------------------------------------------------------------------

std::string encrypt(std::string passwd, std::string plaintext);
std::string decrypt(std::string passwd, std::string ciphertext);

// ----------------------------------------------------------------------
