# 🔐 PyCppCrypt

A command-line AES-256-GCM encryption project that combines a Python interface with a C++17/OpenSSL cryptographic core.

> **Educational alpha software.** Review and audit it before using it for valuable or irreplaceable data. Always keep backups.

## Features

- AES-256-GCM authenticated encryption
- File and UTF-8 text encryption
- C++17/OpenSSL backend exposed to Python through `ctypes`
- PyCryptodome reference backend for interoperability and benchmarking
- Password-protected 256-bit key files using `scrypt` + AES-256-GCM
- Authenticated file metadata and tamper detection
- Atomic output writes: unauthenticated plaintext is never written
- Cross-platform CMake build
- Pytest test suite

## Project structure

```text
PyCppCrypt/
├── cpp/
│   ├── crypt.cpp
│   ├── crypt.h
│   ├── bridge.cpp
│   └── benchmark.cpp
├── pycppcrypt/
│   ├── __init__.py
│   ├── cli.py
│   ├── key_manager.py
│   ├── file_format.py
│   └── wrapper.py
├── tests/
│   ├── test_text.py
│   ├── test_files.py
│   └── test_tampering.py
├── CMakeLists.txt
├── pyproject.toml
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore
```

## Requirements

- Python 3.10+
- CMake 3.16+
- A C++17 compiler
- OpenSSL development files

Ubuntu/Debian example:

```bash
sudo apt update
sudo apt install build-essential cmake libssl-dev python3-venv
```

## Build and install

```bash
git clone https://github.com/sparkj365-create/PyCppCrypt.git
cd PyCppCrypt

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

The Python wrapper searches common `build/` locations. You may also set an explicit path:

```bash
export PYCPPCRYPT_LIB="$PWD/build/libpycppcrypt.so"
```

Windows PowerShell example:

```powershell
$env:PYCPPCRYPT_LIB = "$PWD\build\Release\pycppcrypt.dll"
```

## CLI usage

Create a password-protected AES key file:

```bash
pycppcrypt keygen --out keys/main.key.json
```

Encrypt and decrypt a file with the C++ backend:

```bash
pycppcrypt encrypt-file photo.jpg photo.jpg.pcc --key keys/main.key.json --fast
pycppcrypt decrypt-file photo.jpg.pcc restored-photo.jpg --key keys/main.key.json --fast
```

Encrypt and decrypt text:

```bash
pycppcrypt encrypt-text "Hello from PyCppCrypt" --key keys/main.key.json --fast
pycppcrypt decrypt-text "PASTE_BASE64_TOKEN_HERE" --key keys/main.key.json --fast
```

Use the Python reference backend:

```bash
pycppcrypt encrypt-file input.bin output.pcc --key keys/main.key.json --python
```

Benchmark both backends:

```bash
pycppcrypt benchmark --size-mb 32 --rounds 5
```

Standalone C++ benchmark:

```bash
./build/pycppcrypt_benchmark 64 5
```

## Tests

Build the C++ shared library first, then run:

```bash
pytest
```

The tests cover:

- Empty, English, and Persian text round trips
- C++ ↔ Python interoperability
- Binary file container parsing
- Password-protected key files
- Modified ciphertext and header rejection
- Wrong key-file password rejection

## Security design

- A fresh random 96-bit nonce is generated for every AES-GCM encryption.
- The fixed header and nonce are supplied as Additional Authenticated Data (AAD).
- A 128-bit authentication tag detects wrong keys and modified data.
- Key files do **not** store the AES key as plaintext. The key is encrypted using a key derived from the user's password with `scrypt`.
- Decrypted files are written only after authentication succeeds.

## Current limitations

- The current C API processes the complete input in memory and rejects single buffers larger than `INT_MAX` bytes. Streaming/chunked encryption is a future improvement.
- Passwords and key material exist in Python-managed memory and cannot be reliably wiped.
- This project has not received an independent security audit.
- The `--fast` name selects the C++ backend; actual speed depends on CPU, OpenSSL build, and hardware acceleration.

## License

MIT License.

## Test results

Output of `pytest -v` from GitHub Actions (Python 3.12):

```text
tests/test_files.py::test_binary_container_roundtrip PASSED              [ 11%]
tests/test_files.py::test_password_protected_key_file PASSED             [ 22%]
tests/test_tampering.py::test_modified_ciphertext_is_rejected PASSED     [ 33%]
tests/test_tampering.py::test_modified_authenticated_header_is_rejected PASSED [ 44%]
tests/test_tampering.py::test_wrong_key_password_is_rejected PASSED      [ 55%]
tests/test_text.py::test_text_roundtrip[] PASSED                         [ 66%]
tests/test_text.py::test_text_roundtrip[hello] PASSED                    [ 77%]
tests/test_text.py::test_text_roundtrip[\xd9\x85\xd8\xaa\xd9\x86 \xd9\x81\xd8\xa7\xd8\xb1\xd8\xb3\xdb\x8c \xf0\x9f\x94\x90] PASSED [ 88%]
tests/test_text.py::test_cpp_and_python_interoperate PASSED              [100%]
============================== 9 passed in 0.28s ===============================
```
