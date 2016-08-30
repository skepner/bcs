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

class Buffer
{
      // Bytes
      // 0-3 - signature BCSD
      // 4 - version (1)
      // 5 - algorithm, 1 - EVP_aes_256_cbc
      // 6 - IV size (4-byte words)
      // 7 - ciphertext offset (4-byte words)
      // 8 - IV
      // [3] -  ciphertext

 private:
    static constexpr const size_t IV_OFFSET = 8;
    static constexpr const size_t IV_SIZE = 32;
    static constexpr const size_t INITIAL_SIZE = 8 + IV_SIZE;

    static constexpr const size_t VERSION_OFFSET = 4;
    static constexpr const size_t ALGORITHM_OFFSET = 5;
    static constexpr const size_t IV_SIZE_OFFSET = 6;
    static constexpr const size_t CIPHERTEXT_OFFSET_OFFSET = 7;

 public:
    inline Buffer()
        : data(new unsigned char[INITIAL_SIZE]), reserved(0), used(0)
        {
            std::memcpy(data, "BCSD", 4);
            data[VERSION_OFFSET] = 1;        // version
            data[ALGORITHM_OFFSET] = 1;        // EVP_aes_256_cbc
            data[IV_SIZE_OFFSET] = IV_SIZE / 4;
            data[CIPHERTEXT_OFFSET_OFFSET] = (IV_OFFSET + IV_SIZE) / 4;
            make_iv();
        }

    inline ~Buffer()
        {
            delete [] data;
        }

    inline size_t iv_size() const { return data[IV_SIZE_OFFSET] * 4; }
    inline const unsigned char* iv() const { return data + IV_OFFSET; }
    inline unsigned char* iv() { return data + IV_OFFSET; }

    inline void dump() const
        {
            BIO_dump_fp(stdout, reinterpret_cast<const char*>(data), static_cast<int>(ciphertext_offset() + used));
        }

    typedef const EVP_CIPHER* (*CIPHER)();

    inline CIPHER algorithm() const
        {
            switch (data[ALGORITHM_OFFSET]) {
              case 1:
                  return EVP_aes_256_cbc;
              default:
                  throw std::runtime_error("Unsupported algorithm id: " + std::to_string(static_cast<unsigned>(data[ALGORITHM_OFFSET])));
            }
        }

    inline void reserve(size_t aSize)
        {
            if (aSize > reserved) {
                unsigned char* buf = new unsigned char[ciphertext_offset() + aSize];
                memcpy(buf, data, ciphertext_offset() + used);
                delete [] data;
                data = buf;
                reserved = aSize;
            }
        }

    inline void use_add(int aUse) { used += static_cast<size_t>(aUse); }
    inline size_t ciphertext_size() const { return used; }

    inline unsigned char* ciphertext() { return data + ciphertext_offset(); }
    inline const unsigned char* ciphertext() const { return data + ciphertext_offset(); }
    inline unsigned char* ciphertext_end() { return data + ciphertext_offset() + used; }

 private:
    unsigned char* data;
    size_t reserved, used;

    inline size_t ciphertext_offset() const { return data[CIPHERTEXT_OFFSET_OFFSET] * 4; }

    inline void make_iv()
        {
            srandomdev();
            for (size_t i = 0; i < iv_size(); ++i)
                data[i + IV_OFFSET] = random() & 0xFF;
        }
};

// ----------------------------------------------------------------------

class Bsc
{
 private:
    static constexpr const size_t KEY_SIZE = 32;

 public:
    inline Bsc(std::string aKey)
        {
            std::memcpy(mKey, aKey.c_str(), KEY_SIZE);
            ERR_load_crypto_strings();
            OpenSSL_add_all_algorithms();
            OPENSSL_config(nullptr);
        }

    inline ~Bsc()
        {
            EVP_cleanup();
            ERR_free_strings();
        }

    inline void encrypt(Buffer& aBuffer, std::string aPlainText)
        {
            Context context;
            if (EVP_EncryptInit_ex(context, aBuffer.algorithm()(), nullptr, key(), aBuffer.iv()) != 1)
                error("EVP_EncryptInit_ex");
            aBuffer.reserve(aPlainText.size() * 2);
            int len;
            if (EVP_EncryptUpdate(context, aBuffer.ciphertext(), &len, reinterpret_cast<const unsigned char*>(aPlainText.c_str()), static_cast<int>(aPlainText.size())) != 1)
                error("EVP_EncryptUpdate");
              // std::cout << "EVP_EncryptUpdate " << len << std::endl;
            aBuffer.use_add(len);
            if (EVP_EncryptFinal_ex(context, aBuffer.ciphertext_end(), &len) != 1)
                error("EVP_EncryptFinal_ex");
              // std::cout << "EVP_EncryptFinal " << len << std::endl;
            aBuffer.use_add(len);
        }

    inline std::string decrypt(const Buffer& aBuffer)
        {
            Context context;
            if (EVP_DecryptInit_ex(context, aBuffer.algorithm()(), nullptr, key(), aBuffer.iv()) != 1)
                  error("EVP_DecryptInit_ex");
            std::string plaintext(aBuffer.ciphertext_size() * 2, '#');
            int len1;
            if (EVP_DecryptUpdate(context, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(plaintext.data())), &len1, aBuffer.ciphertext(), static_cast<int>(aBuffer.ciphertext_size())) != 1)
                  error("EVP_DecryptUpdate");
              // std::cout << "len1 " << len1 << std::endl;
            int len2;
            if (EVP_DecryptFinal_ex(context, const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(plaintext.data() + len1)), &len2) != 1)
                  error("EVP_DecryptFinal_ex");
              // std::cout << "len2 " << len2 << std::endl;
            plaintext.resize(static_cast<size_t>(len1 + len2));
            return plaintext;
        }

 private:
    unsigned char mKey[KEY_SIZE];

    inline const unsigned char* key()
        {
            return mKey;
        }

     [[noreturn]] static inline void error(std::string func)
        {
            throw std::runtime_error(func + " failed: " + ERR_error_string(ERR_get_error(), nullptr));
        }

    class Context
    {
     public:
        inline Context()
            : context(EVP_CIPHER_CTX_new())
            {
                if (!context)
                    Bsc::error("EVP_CIPHER_CTX_new");
            }

        inline ~Context()
            {
                EVP_CIPHER_CTX_free(context);
            }

        inline operator EVP_CIPHER_CTX* () { return context; }

     private:
        EVP_CIPHER_CTX* context;
    };
};

// ----------------------------------------------------------------------

int main (void)
{
    std::string key = "01234567890123456789012345678901";
    std::string plaintext = "1 The quick brown fox jumps over the lazy dog\n2 The quick brown fox jumps over the lazy dog\n3 The quick brown fox jumps over the lazy dog\n4 The quick brown fox jumps over the lazy dog";

    Bsc bsc(key);
    Buffer buffer;
    bsc.encrypt(buffer, plaintext);
    buffer.dump();

    auto decrypted = bsc.decrypt(buffer);
    std::cout << "decrypted: " << decrypted << std::endl;

    return 0;
}

// ----------------------------------------------------------------------
