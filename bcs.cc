#include <iostream>
#include <fstream>
#include <sstream>
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
    std::string passwd = "0";
    std::string plaintext = "1 The quick brown fox jumps over the lazy dog\n2 The quick brown fox jumps over the lazy dog\n3 The quick brown fox jumps over the lazy dog\n4 The quick brown fox jumps over the lazy dog";

    std::string ciphertext = encrypt(passwd, plaintext);
    std::cout << "Plaintext size: " << plaintext.size() << std::endl;
    std::cout << "Ciphertext size: " << ciphertext.size() << std::endl;

    std::ofstream out("/tmp/out.aes");
    out.write(ciphertext.c_str(), static_cast<std::streamsize>(ciphertext.size()));
    out.close();

    std::string decrypted = decrypt(passwd, ciphertext);
    if (decrypted != plaintext) {
        std::cerr << decrypted << std::endl;
        throw std::runtime_error("decrypted text does not match source");
    }
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

static inline void hash_password(std::string passwd_s, unsigned char* IV, unsigned char* digest)
{
    unsigned char passwd[MAX_PASSWD_LEN+1];
    const size_t passlen = static_cast<size_t>(passwd_to_utf16(reinterpret_cast<unsigned char*>(const_cast<char*>(passwd_s.c_str())), static_cast<int>(passwd_s.size()), MAX_PASSWD_LEN, passwd));
    sha256_context sha_ctx;

      // Hash the IV and password 8192 times
    memset(digest, 0, 32);
    memcpy(digest, IV, 16);
    for (size_t i = 0; i < 8192; ++i) {
        sha256_starts(&sha_ctx);
        sha256_update(&sha_ctx, digest, 32);
        sha256_update(&sha_ctx, passwd, passlen);
        sha256_finish(&sha_ctx, digest);
    }
}

// ----------------------------------------------------------------------

std::string encrypt(std::string passwd_s, std::string plaintext)
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

    hash_password(passwd_s, IV, digest);

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

inline std::streamsize fread(void* buffer, std::streamsize count, std::istringstream& stream, bool throw_on_fewer_bytes_read = true)
{
    stream.read(reinterpret_cast<char*>(buffer), count);
    const auto gcount = stream.gcount();
    if (gcount < count && throw_on_fewer_bytes_read)
        throw std::runtime_error("input is too short");
    return gcount;
}

// ----------------------------------------------------------------------

std::string decrypt(std::string passwd_s, std::string ciphertext)
{
    std::istringstream infp(ciphertext);

    unsigned char buffer[64], buffer2[32];

    /* Read the file header */
    aescrypt_hdr aeshdr;
    fread(&aeshdr, sizeof(aeshdr), infp);

    if (!(aeshdr.aes[0] == 'A' && aeshdr.aes[1] == 'E' && aeshdr.aes[2] == 'S'))
        throw std::runtime_error("Bad file header (not aescrypt file or is corrupted?)");

    /* Validate the version number and take any version-specific actions */
    if (aeshdr.version == 0)
    {
        /*
         * Let's just consider the least significant nibble to determine
         * the size of the last block
         */
        aeshdr.last_block_size = (aeshdr.last_block_size & 0x0F);
    }
    else if (aeshdr.version > 0x02)
    {
        throw std::runtime_error("Error: Unsupported AES data version");
    }

      // Skip over extensions present v2 and later files
    if (aeshdr.version >= 0x02) {
        std::streamsize j = 1;
        while (j) {
              // Determine the extension length, zero means no more extensions
            fread(buffer, 2, infp);
            j = (static_cast<std::streamsize>(buffer[0]) << 8) | static_cast<std::streamsize>(buffer[1]);
            infp.ignore(j);
            if (!infp)
                throw std::runtime_error("input is too short");
        }
    }

    /* Read the initialization vector from the file */
    unsigned char IV[16];
    fread(IV, 16, infp);

    sha256_t digest;
    hash_password(passwd_s, IV, digest);

    /* Set the AES encryption key */
    aes_context aes_ctx;
    aes_set_key(&aes_ctx, digest, 256);

    unsigned char ipad[64], opad[64];
    set_ipad_opad(ipad, opad, digest);

    sha256_context sha_ctx;
    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, ipad, 64);

    /* If this is a version 1 or later file, then read the IV and key
     * for decrypting the bulk of the file.
     */
    if (aeshdr.version >= 0x01) {
        unsigned char iv_key[48];
        for(size_t i=0; i<48; i+=16) {
            fread(buffer, 16, infp);
            memcpy(buffer2, buffer, 16);

            sha256_update(&sha_ctx, buffer, 16);
            aes_decrypt(&aes_ctx, buffer, buffer);

            /*
             * XOR plain text block with previous encrypted
             * output (i.e., use CBC)
             */
            for(size_t j=0; j<16; ++j)
                iv_key[i+j] = (buffer[j] ^ IV[j]);

            /* Update the IV (CBC mode) */
            memcpy(IV, buffer2, 16);
        }

        /* Verify that the HMAC is correct */
        sha256_finish(&sha_ctx, digest);
        sha256_starts(&sha_ctx);
        sha256_update(&sha_ctx, opad, 64);
        sha256_update(&sha_ctx, digest, 32);
        sha256_finish(&sha_ctx, digest);

        fread(buffer, 32, infp);

        if (memcmp(digest, buffer, 32))
            throw std::runtime_error("Message has been altered or password is incorrect");

        /*
         * Re-load the IV and encryption key with the IV and
         * key to now encrypt the datafile.  Also, reset the HMAC
         * computation.
         */
        memcpy(IV, iv_key, 16);

        /* Set the AES encryption key */
        aes_set_key(&aes_ctx, iv_key+16, 256);

        set_ipad_opad(ipad, opad, iv_key + 16);

        /* Wipe the IV and encryption key from memory */
        memset_secure(iv_key, 0, 48);

        sha256_starts(&sha_ctx);
        sha256_update(&sha_ctx, ipad, 64);
    }

    /*
     * Decrypt the balance of the file
     *
     * Attempt to initialize the ring buffer with contents from the file.
     * Attempt to read 48 octets of the file into the ring buffer.
     */
    bool reached_eof = false;
    std::streamsize bytes_read;
    if ((bytes_read = fread(buffer, 48, infp)) < 48) {
            /*
             * If there are less than 48 octets, the only valid count
             * is 32 for version 0 (HMAC) and 33 for version 1 or
             * greater files ( file size modulo + HMAC)
             */
            if ((aeshdr.version == 0x00 && bytes_read != 32) || (aeshdr.version >= 0x01 && bytes_read != 33)) {
                throw std::runtime_error("Input is corrupt");
            }
            else {
                /*
                 * Version 0 files would have the last block size
                 * read as part of the header, so let's grab that
                 * value now for version 1 files.
                 */
                if (aeshdr.version >= 0x01)
                {
                    /*
                     * The first octet must be the indicator of the
                     * last block size.
                     */
                    aeshdr.last_block_size = (buffer[0] & 0x0F);
                }
                /*
                 * If this initial read indicates there is no encrypted
                 * data, then there should be 0 in the last_block_size field
                 */
                if (aeshdr.last_block_size != 0)
                    throw std::runtime_error("Input file is corrupt");
            }
            reached_eof = true;
    }
    unsigned char* head = buffer + 48;
    unsigned char* tail = buffer;

    std::string plaintext;
    while(!reached_eof)
    {
        /*
         * Check to see if the head of the buffer is past the ring buffer
         */
        if (head == (buffer + 64))
        {
            head = buffer;
        }

        if ((bytes_read = fread(head, 16, infp, false)) < 16)
        {
                /* The last block for v0 must be 16 and for v1 it must be 1 */
                if ((aeshdr.version == 0x00 && bytes_read > 0) || (aeshdr.version >= 0x01 && bytes_read != 1))
                    throw std::runtime_error("Input is corrupt");

                /*
                 * If this is a v1 file, then the file modulo is located
                 * in the ring buffer at tail + 16 (with consideration
                 * given to wrapping around the ring, in which case
                 * it would be at buffer[0])
                 */
                if (aeshdr.version >= 0x01) {
                    if ((tail + 16) < (buffer + 64))
                        aeshdr.last_block_size = (tail[16] & 0x0F);
                    else
                        aeshdr.last_block_size = (buffer[0] & 0x0F);
                }

                /* Indicate that we've reached the end of the file */
                reached_eof = true;
        }

        /*
         * Process data that has been read.  Note that if the last
         * read operation returned no additional data, there is still
         * one one ciphertext block for us to process if this is a v0 file.
         */
        if (bytes_read > 0 || aeshdr.version == 0x00) {
            /* Advance the head of the buffer forward */
            if (bytes_read > 0)
                head += 16;

            memcpy(buffer2, tail, 16);

            sha256_update(&sha_ctx, tail, 16);
            aes_decrypt(&aes_ctx, tail, tail);

            /*
             * XOR plain text block with previous encrypted
             * output (i.e., use CBC)
             */
            for (size_t i=0; i<16; ++i)
                tail[i] ^= IV[i];

            /* Update the IV (CBC mode) */
            memcpy(IV, buffer2, 16);

            /*
             * If this is the final block, then we may
             * write less than 16 octets
             */
            /* Write the decrypted block */
            plaintext.append(reinterpret_cast<char*>(tail), ((!reached_eof) || (aeshdr.last_block_size == 0)) ? 16 : aeshdr.last_block_size);

            /* Move the tail of the ring buffer forward */
            tail += 16;
            if (tail == (buffer+64))
                tail = buffer;
        }
    }

    /* Verify that the HMAC is correct */
    sha256_finish(&sha_ctx, digest);
    sha256_starts(&sha_ctx);
    sha256_update(&sha_ctx, opad, 64);
    sha256_update(&sha_ctx, digest, 32);
    sha256_finish(&sha_ctx, digest);

    /* Copy the HMAC read from the file into buffer2 */
    if (aeshdr.version == 0x00) {
        memcpy(buffer2, tail, 16);
        tail += 16;
        if (tail == (buffer + 64))
            tail = buffer;
        memcpy(buffer2+16, tail, 16);
    }
    else {
        memcpy(buffer2, tail+1, 15);
        tail += 16;
        if (tail == (buffer + 64))
            tail = buffer;
        memcpy(buffer2+15, tail, 16);
        tail += 16;
        if (tail == (buffer + 64))
            tail = buffer;
        memcpy(buffer2+31, tail, 1);
    }

    if (memcmp(digest, buffer2, 32)) {
        if (aeshdr.version == 0x00)
            throw std::runtime_error("Message has been altered or password is incorrect");
        else
            throw std::runtime_error("Message has been altered and should not be trusted");
    }

    return plaintext;

} // decrypt

// ----------------------------------------------------------------------
