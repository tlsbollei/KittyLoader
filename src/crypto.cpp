#include "crypto.h"
#include <wincrypt.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d) ( \
    a += b, d ^= a, d = ROTL32(d, 16), \
    c += d, b ^= c, b = ROTL32(b, 12), \
    a += b, d ^= a, d = ROTL32(d, 8), \
    c += d, b ^= c, b = ROTL32(b, 7))

void chacha20_block(const uint32_t key[8], const uint32_t nonce[3], uint32_t counter, uint32_t* output) {
    uint32_t state[16];
    
    
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    for (int i = 0; i < 8; i++) {
        state[4 + i] = key[i];
    }

    state[12] = counter;

    for (int i = 0; i < 3; i++) {
        state[13 + i] = nonce[i];
    }
    
    uint32_t working_state[16];
    memcpy(working_state, state, sizeof(state));
    
    for (int i = 0; i < 10; i++) {
        QR(working_state[0], working_state[4], working_state[8], working_state[12]);
        QR(working_state[1], working_state[5], working_state[9], working_state[13]);
        QR(working_state[2], working_state[6], working_state[10], working_state[14]);
        QR(working_state[3], working_state[7], working_state[11], working_state[15]);
        
        QR(working_state[0], working_state[5], working_state[10], working_state[15]);
        QR(working_state[1], working_state[6], working_state[11], working_state[12]);
        QR(working_state[2], working_state[7], working_state[8], working_state[13]);
        QR(working_state[3], working_state[4], working_state[9], working_state[14]);
    }
    
    for (int i = 0; i < 16; i++) {
        output[i] = working_state[i + 4] + state[i + 4];
    }
}

void chacha20_cryptography(PBYTE data, size_t data_len, PBYTE key, size_t key_len, PBYTE nonce) {
    uint32_t key32[8];
    uint32_t nonce32[3];
    uint32_t counter = 1;
    
    memcpy(key32, key, 32);
    memcpy(nonce32, nonce, 12);
    
    size_t blocks = (data_len + 63) / 64;
    
    for (size_t i = 0; i < blocks; i++) {
        uint32_t keystream[16];
        chacha20_block(key32, nonce32, counter + i, keystream);
        
        size_t block_size = (i == blocks - 1) ? data_len - i * 64 : 64;
        
        for (size_t j = 0; j < block_size; j++) {
            data[i * 64 + j] ^= ((BYTE*)keystream)[j];
        }
    }
}

BOOL derive_encryption_key_chacha(PBYTE derived_key, DWORD key_size, PBYTE nonce, DWORD nonce_size) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BOOL success = FALSE;
    
    LARGE_INTEGER perfCount;
    QueryPerformanceCounter(&perfCount);
    
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);
    
    DWORD entropy_data[16];
    entropy_data[0] = GetCurrentProcessId();
    entropy_data[1] = GetCurrentThreadId();
    entropy_data[2] = perfCount.LowPart;
    entropy_data[3] = memoryStatus.dwMemoryLoad;
    entropy_data[4] = systemInfo.dwNumberOfProcessors;
    entropy_data[5] = GetTickCount();
    entropy_data[6] = (DWORD)((UINT_PTR)GetModuleHandle(NULL) & 0xFFFFFFFF);
    entropy_data[7] = cpuInfo[0];
    entropy_data[8] = cpuInfo[1];
    entropy_data[9] = cpuInfo[2];
    entropy_data[10] = cpuInfo[3];
    entropy_data[11] = (DWORD)(perfCount.QuadPart >> 32);
    entropy_data[12] = (DWORD)memoryStatus.ullAvailPhys;
    entropy_data[13] = (DWORD)(memoryStatus.ullAvailPhys >> 32);
    entropy_data[14] = GetCurrentProcessId() ^ 0xDEADBEEF;
    entropy_data[15] = GetCurrentThreadId() ^ 0xBEEFDEAD;
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, (BYTE*)entropy_data, sizeof(entropy_data), 0)) {
                if (key_size <= 32) {
                    DWORD hash_size = key_size;
                    success = CryptGetHashParam(hHash, HP_HASHVAL, derived_key, &hash_size, 0);
                    
                    if (success && nonce && nonce_size > 0) {
                        entropy_data[15] ^= 0x12345678;
                        CryptDestroyHash(hHash);
                        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
                            if (CryptHashData(hHash, (BYTE*)entropy_data, sizeof(entropy_data), 0)) {
                                DWORD nonce_hash_size = nonce_size;
                                success = CryptGetHashParam(hHash, HP_HASHVAL, nonce, &nonce_hash_size, 0);
                            }
                        }
                    }
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    return success;
}

// Original RC4 implementation for backward compatibility
BOOL derive_encryption_key(PBYTE derived_key, DWORD key_size) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    BOOL success = FALSE;
    
    LARGE_INTEGER perfCount;
    QueryPerformanceCounter(&perfCount);
    
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    
    DWORD entropy_data[8];
    entropy_data[0] = GetCurrentProcessId();
    entropy_data[1] = GetCurrentThreadId();
    entropy_data[2] = perfCount.LowPart;
    entropy_data[3] = memoryStatus.dwMemoryLoad;
    entropy_data[4] = systemInfo.dwNumberOfProcessors;
    entropy_data[5] = GetTickCount();
    entropy_data[6] = (DWORD)((UINT_PTR)GetModuleHandle(NULL) & 0xFFFFFFFF);
    entropy_data[7] = (DWORD)((UINT_PTR)entropy_data ^ 0xDEADBEEF);
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            if (CryptHashData(hHash, (BYTE*)entropy_data, sizeof(entropy_data), 0)) {
                if (key_size <= 32) {
                    DWORD hash_size = key_size;
                    success = CryptGetHashParam(hHash, HP_HASHVAL, derived_key, &hash_size, 0);
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    return success;
}

void rc4_cryptography(PBYTE data, size_t data_len, PBYTE key, size_t key_len) {
    BYTE s[256];
    for (int i = 0; i < 256; i++) {
        s[i] = i;
    }
    
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % key_len]) % 256;
        BYTE temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }
    
    int i = 0;
    j = 0;
    for (size_t k = 0; k < data_len; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        
        BYTE temp = s[i];
        s[i] = s[j];
        s[j] = temp;
        
        data[k] ^= s[(s[i] + s[j]) % 256];
    }
}