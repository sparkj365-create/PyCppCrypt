#include "crypt.h"

#include <climits>
#include <memory>

#include <openssl/evp.h>

namespace pycppcrypt {
namespace {

constexpr std::size_t AES_256_KEY_SIZE = 32;
constexpr std::size_t GCM_NONCE_SIZE = 12;
constexpr std::size_t GCM_TAG_SIZE = 16;

using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

bool fits_openssl_int(std::size_t value) {
    return value <= static_cast<std::size_t>(INT_MAX);
}

bool valid_common_args(
    const std::uint8_t* key,
    std::size_t key_len,
    const std::uint8_t* nonce,
    std::size_t nonce_len,
    std::size_t input_len,
    std::size_t aad_len,
    std::size_t tag_len
) {
    if (key == nullptr || nonce == nullptr) {
        return false;
    }
    if (key_len != AES_256_KEY_SIZE || nonce_len != GCM_NONCE_SIZE || tag_len != GCM_TAG_SIZE) {
        return false;
    }
    return fits_openssl_int(input_len) && fits_openssl_int(aad_len) &&
           fits_openssl_int(nonce_len) && fits_openssl_int(tag_len);
}

}  // namespace

CryptoResult aes256_gcm_encrypt(
    const std::uint8_t* plaintext,
    std::size_t plaintext_len,
    const std::uint8_t* key,
    std::size_t key_len,
    const std::uint8_t* nonce,
    std::size_t nonce_len,
    const std::uint8_t* aad,
    std::size_t aad_len,
    std::uint8_t* ciphertext,
    std::uint8_t* tag,
    std::size_t tag_len
) {
    if (!valid_common_args(key, key_len, nonce, nonce_len, plaintext_len, aad_len, tag_len)) {
        return CryptoResult::Error;
    }
    if ((plaintext_len > 0 && (plaintext == nullptr || ciphertext == nullptr)) || tag == nullptr) {
        return CryptoResult::Error;
    }
    if (aad_len > 0 && aad == nullptr) {
        return CryptoResult::Error;
    }

    CtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        return CryptoResult::Error;
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return CryptoResult::Error;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce_len), nullptr) != 1) {
        return CryptoResult::Error;
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key, nonce) != 1) {
        return CryptoResult::Error;
    }

    int out_len = 0;
    if (aad_len > 0 &&
        EVP_EncryptUpdate(ctx.get(), nullptr, &out_len, aad, static_cast<int>(aad_len)) != 1) {
        return CryptoResult::Error;
    }

    int total_len = 0;
    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx.get(), ciphertext, &out_len, plaintext,
                              static_cast<int>(plaintext_len)) != 1) {
            return CryptoResult::Error;
        }
        total_len = out_len;
    }

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext + total_len, &out_len) != 1) {
        return CryptoResult::Error;
    }
    total_len += out_len;

    if (static_cast<std::size_t>(total_len) != plaintext_len) {
        return CryptoResult::Error;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(tag_len), tag) != 1) {
        return CryptoResult::Error;
    }

    return CryptoResult::Success;
}

CryptoResult aes256_gcm_decrypt(
    const std::uint8_t* ciphertext,
    std::size_t ciphertext_len,
    const std::uint8_t* key,
    std::size_t key_len,
    const std::uint8_t* nonce,
    std::size_t nonce_len,
    const std::uint8_t* aad,
    std::size_t aad_len,
    const std::uint8_t* tag,
    std::size_t tag_len,
    std::uint8_t* plaintext
) {
    if (!valid_common_args(key, key_len, nonce, nonce_len, ciphertext_len, aad_len, tag_len)) {
        return CryptoResult::Error;
    }
    if ((ciphertext_len > 0 && (ciphertext == nullptr || plaintext == nullptr)) || tag == nullptr) {
        return CryptoResult::Error;
    }
    if (aad_len > 0 && aad == nullptr) {
        return CryptoResult::Error;
    }

    CtxPtr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        return CryptoResult::Error;
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        return CryptoResult::Error;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(nonce_len), nullptr) != 1) {
        return CryptoResult::Error;
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key, nonce) != 1) {
        return CryptoResult::Error;
    }

    int out_len = 0;
    if (aad_len > 0 &&
        EVP_DecryptUpdate(ctx.get(), nullptr, &out_len, aad, static_cast<int>(aad_len)) != 1) {
        return CryptoResult::Error;
    }

    int total_len = 0;
    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx.get(), plaintext, &out_len, ciphertext,
                              static_cast<int>(ciphertext_len)) != 1) {
            return CryptoResult::Error;
        }
        total_len = out_len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag_len), const_cast<std::uint8_t*>(tag)) != 1) {
        return CryptoResult::Error;
    }

    const int final_ok = EVP_DecryptFinal_ex(ctx.get(), plaintext + total_len, &out_len);
    if (final_ok != 1) {
        return CryptoResult::AuthenticationFailed;
    }
    total_len += out_len;

    if (static_cast<std::size_t>(total_len) != ciphertext_len) {
        return CryptoResult::Error;
    }

    return CryptoResult::Success;
}

}  // namespace pycppcrypt
