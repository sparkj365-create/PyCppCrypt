#include "crypt.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <vector>

#include <openssl/rand.h>

int main(int argc, char** argv) {
    std::size_t size_mb = 64;
    int rounds = 5;

    if (argc > 1) {
        size_mb = static_cast<std::size_t>(std::strtoull(argv[1], nullptr, 10));
    }
    if (argc > 2) {
        rounds = std::atoi(argv[2]);
    }
    if (size_mb == 0 || rounds <= 0) {
        std::cerr << "Usage: pycppcrypt_benchmark [size_mb] [rounds]\n";
        return 2;
    }

    const std::size_t size = size_mb * 1024ULL * 1024ULL;
    std::vector<std::uint8_t> plaintext(size);
    std::vector<std::uint8_t> ciphertext(size);
    std::vector<std::uint8_t> key(32);
    std::vector<std::uint8_t> nonce(12);
    std::vector<std::uint8_t> tag(16);

    if (RAND_bytes(plaintext.data(), static_cast<int>(plaintext.size())) != 1 ||
        RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        std::cerr << "OpenSSL random generation failed.\n";
        return 1;
    }

    double total_seconds = 0.0;
    for (int i = 0; i < rounds; ++i) {
        if (RAND_bytes(nonce.data(), static_cast<int>(nonce.size())) != 1) {
            std::cerr << "OpenSSL nonce generation failed.\n";
            return 1;
        }

        const auto start = std::chrono::steady_clock::now();
        const auto result = pycppcrypt::aes256_gcm_encrypt(
            plaintext.data(), plaintext.size(), key.data(), key.size(),
            nonce.data(), nonce.size(), nullptr, 0,
            ciphertext.data(), tag.data(), tag.size());
        const auto end = std::chrono::steady_clock::now();

        if (result != pycppcrypt::CryptoResult::Success) {
            std::cerr << "Encryption failed.\n";
            return 1;
        }

        total_seconds += std::chrono::duration<double>(end - start).count();
    }

    const double total_mb = static_cast<double>(size_mb) * rounds;
    const double throughput = total_mb / total_seconds;

    std::cout << std::fixed << std::setprecision(2)
              << "AES-256-GCM C++/OpenSSL benchmark\n"
              << "Data per round: " << size_mb << " MiB\n"
              << "Rounds: " << rounds << "\n"
              << "Average throughput: " << throughput << " MiB/s\n";
    return 0;
}
