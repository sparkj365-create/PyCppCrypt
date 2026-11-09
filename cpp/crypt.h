#pragma once

#include <cstddef>
#include <cstdint>

namespace pycppcrypt {

enum class CryptoResult : int {
    Error = -1,
    AuthenticationFailed = 0,
    Success = 1,
};

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
);

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
);

}  // namespace pycppcrypt
