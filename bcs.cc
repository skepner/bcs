#ifdef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreserved-id-macro"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#endif

#include <iostream>
#include <string>
#include <cstring>
#include <cstdlib>

// ----------------------------------------------------------------------

void make_iv(unsigned char* buf);
size_t encrypt(const char* plaintext, size_t plaintext_len, std::string key, char* ciphertext);
size_t decrypt(const char* ciphertext, size_t ciphertext_len, std::string key, char* plaintext);

// ----------------------------------------------------------------------

int main (void)
{
    srandomdev();
    std::string key = "01234567890123456789012345678901";

    const char* plaintext = "The quick brown fox jumps over the lazy dog";

      /* Buffer for ciphertext. Ensure the buffer is long enough for the
       * ciphertext which may be longer than the plaintext, dependant on the
       * algorithm and mode
       */
    char ciphertext[1024];

      /* Buffer for the decrypted text */
    char decryptedtext[1024];

    size_t decryptedtext_len, ciphertext_len;

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

      /* Encrypt the plaintext */
    ciphertext_len = encrypt(plaintext, strlen(plaintext), key, ciphertext);

      /* Do something useful with the ciphertext here */
    printf("Ciphertext is: %d\n", ciphertext_len);
    BIO_dump_fp(stdout, ciphertext, static_cast<int>(ciphertext_len));

    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, decryptedtext);

      /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

      /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

// ----------------------------------------------------------------------

constexpr const size_t IV_LEN = 32;

void make_iv(unsigned char* buf)
{
    for (size_t i = 0; i < IV_LEN; ++i)
        buf[i] = random() & 0xFF;

} // make_iv

// ----------------------------------------------------------------------


size_t encrypt(const char* plaintext, size_t plaintext_len, std::string key, char* ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    size_t len;

    size_t ciphertext_len;

      /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    unsigned char key2[32];
    std::memcpy(key2, key.c_str(), 32);
    unsigned char iv[IV_LEN];
    make_iv(iv);
    memcpy(ciphertext, iv, IV_LEN);

    // const unsigned char* key2 = reinterpret_cast<const unsigned char*>(key.c_str());
    // const unsigned char* iv2 = reinterpret_cast<const unsigned char*>(iv.c_str());

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key2, iv))
        throw std::runtime_error("EVP_EncryptInit_ex failed");

      /* Provide the message to be encrypted, and obtain the encrypted output.
       * EVP_EncryptUpdate can be called multiple times if necessary
       */
    if(1 != EVP_EncryptUpdate(ctx, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(ciphertext + IV_LEN)), reinterpret_cast<int*>(&len), reinterpret_cast<const unsigned char*>(plaintext), static_cast<int>(plaintext_len)))
        throw std::runtime_error("EVP_EncryptUpdate failed");
    ciphertext_len = IV_LEN + len;

      /* Finalise the encryption. Further ciphertext bytes may be written at
       * this stage.
       */
    if(1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext + ciphertext_len), reinterpret_cast<int*>(&len)))
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    ciphertext_len += len;

      /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// ----------------------------------------------------------------------

size_t decrypt(const char* ciphertext, size_t ciphertext_len, std::string key, char* plaintext)
{
    unsigned char iv[IV_LEN];
    memcpy(iv, ciphertext, IV_LEN);

    EVP_CIPHER_CTX *ctx;

    int len;

      /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");

      /* Initialise the decryption operation. IMPORTANT - ensure you use a key
       * and IV size appropriate for your cipher
       * In this example we are using 256 bit AES (i.e. a 256 bit key). The
       * IV size for *most* modes is the same as the block size. For AES this
       * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.c_str()), iv))
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    std::cerr << "EVP_DecryptInit_ex" << std::endl;

      /* Provide the message to be decrypted, and obtain the plaintext output.
       * EVP_DecryptUpdate can be called multiple times if necessary
       */
    if(1 != EVP_DecryptUpdate(ctx, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(plaintext)), &len, reinterpret_cast<const unsigned char*>(ciphertext + IV_LEN), static_cast<int>(ciphertext_len - IV_LEN)))
        throw std::runtime_error("EVP_DecryptUpdate failed");
    std::cerr << "EVP_DecryptUpdate " << len << std::endl;
    size_t plaintext_len = len;

      /* Finalise the decryption. Further plaintext bytes may be written at
       * this stage.
       */
    if(1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext + plaintext_len), &len))
        std::cerr << "EVP_DecryptFinal_ex failed: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
        // throw std::runtime_error("EVP_DecryptFinal_ex failed");
    else
        plaintext_len += len;

      /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

// ----------------------------------------------------------------------
