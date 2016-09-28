#include <iostream>
#include <string>
#include <cstring>
// #include <cstdlib>
#include <unistd.h>

#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wreserved-id-macro"
#endif
extern "C" {
#include "config.h"
#include "aescrypt.h"
#include "password.h"
#include "keyfile.h"
#include "util.h"
#include "aesrandom.h"
}
#pragma GCC diagnostic pop

// ----------------------------------------------------------------------

std::string encrypt(std::string passwd, std::string plaintext);
std::string decrypt(std::string passwd, std::string ciphertext);

// ----------------------------------------------------------------------

int main (void)
{
    std::string key = "01234567890123456789012345678901";
    std::string plaintext = "1 The quick brown fox jumps over the lazy dog\n2 The quick brown fox jumps over the lazy dog\n3 The quick brown fox jumps over the lazy dog\n4 The quick brown fox jumps over the lazy dog";

    std::string ciphertext = encrypt(key, plaintext);
    std::cout << "Plaintext size: " << plaintext.size() << std::endl;
    std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;
    std::string decrypted = decrypt(key, ciphertext);
    if (decrypted != plaintext)
        std::cerr << decrypted << std::endl;

    return 0;
}

// ----------------------------------------------------------------------

class AesRandom
{
 public:
    inline AesRandom()
        : mAesrand(aesrandom_open())
        {
            if (mAesrand == nullptr)
                throw std::runtime_error(std::string("aesrandom_open: ") + std::strerror(errno));
        }

    inline ~AesRandom()
        {
            if (mAesrand != nullptr)
                aesrandom_close(mAesrand);
        }

    inline void read(unsigned char buffer[32])
        {
            const auto bytes_read = aesrandom_read(mAesrand, buffer, 32);
            if (bytes_read != 32)
                throw std::runtime_error("aesrandom_read failed");
        }

 private:
    void* mAesrand;
};

// ----------------------------------------------------------------------

static inline void set_ipad_opad(unsigned char ipad[64], unsigned char opad[64], const unsigned char* digest)
{
    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);
    for (size_t i = 0; i < 32; ++i) {
        ipad[i] ^= digest[i];
        opad[i] ^= digest[i];
    }
}

// ----------------------------------------------------------------------

std::string encrypt(std::string passwd, std::string plaintext)
{
    AesRandom aesrand;

    sha256_context sha_ctx;
    sha256_t digest;

    unsigned char iv_key[48];
    memset(iv_key, 0, 48);
    unsigned char buffer[32];
    for (int i = 0; i < 48; i += 16) {
        memset(buffer, 0, 32);
        sha256_starts(&sha_ctx);
        for (int j = 0; j < 256; ++j) {
            aesrand.read(buffer);
            sha256_update(&sha_ctx, buffer, 32);
        }
        sha256_finish(&sha_ctx, digest);
        memcpy(iv_key + i, digest, 16);
    }

    std::string ciphertext;
    ciphertext.append("AES\x02\x00", 5); // signature

    const size_t created_by_size = 11 + strlen(PACKAGE_NAME) + 1 + strlen(PACKAGE_VERSION);
    if (created_by_size < 256) {
        ciphertext.append(1, 0);
        ciphertext.append(1, static_cast<unsigned char>(created_by_size & 0xFF));
        ciphertext.append("CREATED_BY", 11);
        ciphertext.append(PACKAGE_NAME);
        ciphertext.append(1, ' ');
        ciphertext.append(PACKAGE_VERSION);
    }

      // Append the "container" extension
    ciphertext.append("\x00\x80", 2);
    ciphertext.append(128, 0);
      // Append 0x0000 to indicate that no more extensions exist
    ciphertext.append(2, 0);

      // initialization vector comprised of the current time process ID, and random data, all hashed together with SHA-256.
    const auto current_time = std::time(nullptr);
    for (size_t i = 0; i < 8; ++i)
        buffer[i] = static_cast<unsigned char>(current_time >> (i * 8));
    const auto process_id = getpid();
    for (size_t i = 0; i < 8; ++i)
        buffer[i+8] = static_cast<unsigned char>(process_id >> (i * 8));
    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, buffer, 16);
    for (size_t i = 0; i < 256; ++i) {
        aesrand.read(buffer);
        sha256_update(&sha_ctx, buffer, 32);
    }
    sha256_finish(&sha_ctx, digest);
    unsigned char IV[16];
    memcpy(IV, digest, 16);
    ciphertext.append(reinterpret_cast<char*>(IV), 16);

      // Hash the IV and password 8192 times
    memset(digest, 0, 32);
    memcpy(digest, IV, 16);
    for (size_t i = 0; i < 8192; ++i) {
        sha256_starts(&sha_ctx);
        sha256_update(&sha_ctx, digest, 32);
        sha256_update(&sha_ctx, reinterpret_cast<unsigned char*>(const_cast<char*>(passwd.c_str())), passwd.size());
        sha256_finish(&sha_ctx, digest);
    }

    aes_context aes_ctx;
    aes_set_key(&aes_ctx, digest, 256);

    unsigned char ipad[64], opad[64];
    set_ipad_opad(ipad, opad, digest);
    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, ipad, 64);

     // Encrypt the IV and key used to encrypt the plaintext, append that encrypted text to the output.
    for (int i = 0; i < 48; i += 16) {
          // Place the next 16 octets of IV and key buffer into the input buffer.
        memcpy(buffer, iv_key + i, 16);
          // XOR plain text block with previous encrypted output (i.e., use CBC)
        for (size_t j = 0; j < 16; ++j)
            buffer[j] ^= IV[j];
          // Encrypt the contents of the buffer
        aes_encrypt(&aes_ctx, buffer, buffer);
          // Concatenate the "text" as we compute the HMAC
        sha256_update(&sha_ctx, buffer, 16);
          // Append the encrypted block to output
        ciphertext.append(reinterpret_cast<char*>(buffer), 16);
          // Update the IV (CBC mode)
        memcpy(IV, buffer, 16);
    }

      // Append the HMAC
    sha256_finish(&sha_ctx, digest);
    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, opad, 64);
    sha256_update(&sha_ctx, digest, 32);
    sha256_finish(&sha_ctx, digest);
    ciphertext.append(reinterpret_cast<char*>(digest), 32);

      // Re-load the IV and encryption key with the IV and key to now encrypt the datafile.  Also, reset the HMAC computation.
    memcpy(IV, iv_key, 16);
      // Set the AES encryption key
    aes_set_key(&aes_ctx, iv_key + 16, 256);
      // Set the ipad and opad arrays with values as per RFC 2104 (HMAC).  HMAC is defined as H(K XOR opad, H(K XOR ipad, text))
    set_ipad_opad(ipad, opad, iv_key + 16);
      // Wipe the IV and encryption key from memory
    memset_secure(iv_key, 0, 48);

    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, ipad, 64);

      /// Initialize the last_block_size value to 0
    size_t last_block_size = 0;

    for (size_t input_offset = 0; input_offset < plaintext.size(); input_offset += 16) {
          // while ((bytes_read = fread(buffer, 1, 16, infp)) > 0)
        last_block_size = std::min(16UL, plaintext.size() - input_offset);
        memcpy(buffer, plaintext.c_str() + input_offset, last_block_size);
        for (size_t i = 0; i < 16; ++i)
            buffer[i] ^= IV[i];
        aes_encrypt(&aes_ctx, buffer, buffer);
          // Concatenate the "text" as we compute the HMAC
        sha256_update(&sha_ctx, buffer, 16);
        ciphertext.append(reinterpret_cast<char*>(buffer), 16);
          // Update the IV (CBC mode)
        memcpy(IV, buffer, 16);
    }

      // Append the input size modulo
    ciphertext.append(1, last_block_size & 0x0F);

      // Append the HMAC
    sha256_finish(&sha_ctx, digest);
    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, opad, 64);
    sha256_update(&sha_ctx, digest, 32);
    sha256_finish(&sha_ctx, digest);
    ciphertext.append(reinterpret_cast<char*>(digest), 32);

    return ciphertext;

} // encrypt

// ----------------------------------------------------------------------

std::string decrypt(std::string passwd, std::string ciphertext)
{
    aescrypt_hdr aeshdr;
    memcpy(&aeshdr, ciphertext.c_str(), sizeof(aeshdr));
    if (!(aeshdr.aes[0] == 'A' && aeshdr.aes[1] == 'E' && aeshdr.aes[2] == 'S'))
        throw std::runtime_error("Bad header: no signature");
    if (aeshdr.version == 0) {
          // Let's just consider the least significant nibble to determine the size of the last block
        aeshdr.last_block_size = aeshdr.last_block_size & 0x0F;
    }
    else if (aeshdr.version > 0x02) {
        throw std::runtime_error("Error: Unsupported AES file version");
    }

    size_t input_offset = sizeof(aeshdr);

      // Skip over extensions present v2 and later files
    if (aeshdr.version >= 0x02) {
        size_t j = 1;
        while (j) {
              // Determine the extension length, zero means no more extensions
            j = (static_cast<size_t>(ciphertext[input_offset]) << 8) | static_cast<size_t>(ciphertext[input_offset + 1]);
            input_offset += 2 + j;
            if (input_offset >= ciphertext.size())
                throw std::runtime_error("ciphertext is too short input_offset:" + std::to_string(input_offset) + " ciphertext:" + std::to_string(ciphertext.size()));
        }
    }

      // Get the initialization vector
    if ((input_offset + 16) > ciphertext.size())
        throw std::runtime_error("ciphertext is too short");
    unsigned char IV[16];
    memcpy(IV, ciphertext.c_str() + input_offset, 16);

    // Hash the IV and password 8192 times
    sha256_context sha_ctx;
    sha256_t digest;
    memset(digest, 0, 32);
    memcpy(digest, IV, 16);
    for (size_t i = 0; i < 8192; ++i) {
        sha256_starts(&sha_ctx);
        sha256_update(&sha_ctx, digest, 32);
        sha256_update(&sha_ctx, reinterpret_cast<unsigned char*>(const_cast<char*>(passwd.c_str())), passwd.size());
        sha256_finish(&sha_ctx, digest);
    }

      /// Set the AES encryption key
    aes_context aes_ctx;
    aes_set_key(&aes_ctx, digest, 256);
      // Set the ipad and opad arrays with values as per RFC 2104 (HMAC).  HMAC is defined as  H(K XOR opad, H(K XOR ipad, text))
    unsigned char ipad[64], opad[64];
    set_ipad_opad(ipad, opad, digest);
    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, ipad, 64);

    // aescrypt_hdr aeshdr;
    // unsigned char iv_key[48];
    // unsigned i, j, n;
    // size_t bytes_read;
    // unsigned char buffer[64], buffer2[32];
    // unsigned char *head, *tail;
    // int reached_eof = 0;

    std::string plaintext; //(ciphertext.size() + 256, 0);
    return plaintext;

} // decrypt

// ----------------------------------------------------------------------
