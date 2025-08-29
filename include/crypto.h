#pragma once

#include <windows.h>

BOOL derive_encryption_key_chacha(PBYTE derived_key, DWORD key_size, PBYTE nonce, DWORD nonce_size);
void chacha20_cryptography(PBYTE data, size_t data_len, PBYTE key, size_t key_len, PBYTE nonce);

// Original functions for backward compatibility
BOOL derive_encryption_key(PBYTE derived_key, DWORD key_size);
void rc4_cryptography(PBYTE data, size_t data_len, PBYTE key, size_t key_len);