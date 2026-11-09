#include "crypt.h"

#include <cstddef>
#include <cstdint>

#if defined(_WIN32)
#define PCC_EXPORT extern "C" __declspec(dllexport)
#else
#define PCC_EXPORT extern "C" __attribute__((visibility("default")))
#endif

PCC_EXPORT int pycppcrypt_encrypt(
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
    return static_cast<int>(pycppcrypt::aes256_gcm_encrypt(
        plaintext, plaintext_len, key, key_len, nonce, nonce_len,
        aad, aad_len, ciphertext, tag, tag_len));
}

PCC_EXPORT int pycppcrypt_decrypt(
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
    return static_cast<int>(pycppcrypt::aes256_gcm_decrypt(
        ciphertext, ciphertext_len, key, key_len, nonce, nonce_len,
        aad, aad_len, tag, tag_len, plaintext));
}
