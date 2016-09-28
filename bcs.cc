#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>

// ----------------------------------------------------------------------

int main (void)
{
    std::string key = "01234567890123456789012345678901";
    std::string plaintext = "1 The quick brown fox jumps over the lazy dog\n2 The quick brown fox jumps over the lazy dog\n3 The quick brown fox jumps over the lazy dog\n4 The quick brown fox jumps over the lazy dog";

    // Bsc bsc(key);
    // Buffer buffer;
    // bsc.encrypt(buffer, plaintext);
    // buffer.dump();

    // auto decrypted = bsc.decrypt(buffer);
    // std::cout << "decrypted: " << decrypted << std::endl;

    return 0;
}

// ----------------------------------------------------------------------
