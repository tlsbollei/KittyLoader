#include "crypto.h"
#include <intrin.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <cstring>
#include <cstdint>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

#define rotl32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define qr(a, b, c, d) ( \
    a += b, d ^= a, d = rotl32(d, 16), \
    c += d, b ^= c, b = rotl32(b, 12), \
    a += b, d ^= a, d = rotl32(d, 8), \
    c += d, b ^= c, b = rotl32(b, 7))

void chachablock(const unsigned long key[8], const unsigned long nonce[3], unsigned long counter, unsigned long* output) {
    unsigned long state[16];

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

    unsigned long work[16];
    memcpy(work, state, sizeof(state));

    for (int i = 0; i < 10; i++) {
        qr(work[0], work[4], work[8], work[12]);
        qr(work[1], work[5], work[9], work[13]);
        qr(work[2], work[6], work[10], work[14]);
        qr(work[3], work[7], work[11], work[15]);

        qr(work[0], work[5], work[10], work[15]);
        qr(work[1], work[6], work[11], work[12]);
        qr(work[2], work[7], work[8], work[13]);
        qr(work[3], work[4], work[9], work[14]);
    }

    for (int i = 0; i < 16; i++) {
        output[i] = work[i] + state[i];
    }
}

void chacha_crypt(unsigned char* data, size_t datalen, unsigned char* key, size_t keylen, unsigned char* nonce) {
    unsigned long key32[8];
    unsigned long nonce32[3];
    unsigned long counter = 1;

    memcpy(key32, key, 32);
    memcpy(nonce32, nonce, 12);

    size_t blocks = (datalen + 63) / 64;

    for (size_t i = 0; i < blocks; i++) {
        unsigned long keystream[16];
        chachablock(key32, nonce32, counter + (unsigned long)i, keystream);

        size_t blocksize = (i == blocks - 1) ? datalen - i * 64 : 64;

        for (size_t j = 0; j < blocksize; j++) {
            data[i * 64 + j] ^= ((unsigned char*)keystream)[j];
        }
    }
}

int makechacha(unsigned char* key, unsigned long keysize, unsigned char* nonce, unsigned long noncesize) {
    void* provider;
    void* hash;
    int success = 0;

    LARGE_INTEGER perf;
    QueryPerformanceCounter(&perf);

    MEMORYSTATUSEX memstatus;
    memstatus.dwLength = sizeof(memstatus);
    GlobalMemoryStatusEx(&memstatus);

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    int cpuinfo[4];
    __cpuid(cpuinfo, 0);

    unsigned long entropy[16];
    entropy[0] = GetCurrentProcessId();
    entropy[1] = GetCurrentThreadId();
    entropy[2] = perf.LowPart;
    entropy[3] = memstatus.dwMemoryLoad;
    entropy[4] = sysinfo.dwNumberOfProcessors;
    entropy[5] = GetTickCount();
    entropy[6] = (unsigned long)((unsigned long long)GetModuleHandle(NULL) & 0xFFFFFFFF);
    entropy[7] = cpuinfo[0];
    entropy[8] = cpuinfo[1];
    entropy[9] = cpuinfo[2];
    entropy[10] = cpuinfo[3];
    entropy[11] = (unsigned long)(perf.QuadPart >> 32);
    entropy[12] = (unsigned long)memstatus.ullAvailPhys;
    entropy[13] = (unsigned long)(memstatus.ullAvailPhys >> 32);
    entropy[14] = GetCurrentProcessId() ^ 0xDEADBEEF;
    entropy[15] = GetCurrentThreadId() ^ 0xBEEFDEAD;

    if (CryptAcquireContext((HCRYPTPROV*)&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash((HCRYPTPROV)provider, CALG_SHA_256, 0, 0, (HCRYPTHASH*)&hash)) {
            if (CryptHashData((HCRYPTHASH)hash, (unsigned char*)entropy, sizeof(entropy), 0)) {
                unsigned char fullhash[32];
                unsigned long hashsize = sizeof(fullhash);
                
                if (CryptGetHashParam((HCRYPTHASH)hash, HP_HASHVAL, fullhash, &hashsize, 0)) {
                    unsigned long copysize = (keysize <= hashsize) ? keysize : hashsize;
                    memcpy(key, fullhash, copysize);
                    success = 1;

                    if (success && nonce && noncesize > 0) {
                        entropy[15] ^= 0x12345678;
                        CryptDestroyHash((HCRYPTHASH)hash);
                        if (CryptCreateHash((HCRYPTPROV)provider, CALG_SHA_256, 0, 0, (HCRYPTHASH*)&hash)) {
                            if (CryptHashData((HCRYPTHASH)hash, (unsigned char*)entropy, sizeof(entropy), 0)) {
                                unsigned char noncehash[32];
                                unsigned long noncehashsize = sizeof(noncehash);
                                if (CryptGetHashParam((HCRYPTHASH)hash, HP_HASHVAL, noncehash, &noncehashsize, 0)) {
                                    unsigned long noncecopy = (noncesize <= noncehashsize) ? noncesize : noncehashsize;
                                    memcpy(nonce, noncehash, noncecopy);
                                } else {
                                    success = 0;
                                }
                            } else {
                                success = 0;
                            }
                        } else {
                            success = 0;
                        }
                    }
                }
            }
            CryptDestroyHash((HCRYPTHASH)hash);
        }
        CryptReleaseContext((HCRYPTPROV)provider, 0);
    }

    return success;
}

int makekey(unsigned char* key, unsigned long keysize) {
    void* provider;
    void* hash;
    int success = 0;

    LARGE_INTEGER perf;
    QueryPerformanceCounter(&perf);

    MEMORYSTATUSEX memstatus;
    memstatus.dwLength = sizeof(memstatus);
    GlobalMemoryStatusEx(&memstatus);

    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    unsigned long entropy[8];
    entropy[0] = GetCurrentProcessId();
    entropy[1] = GetCurrentThreadId();
    entropy[2] = perf.LowPart;
    entropy[3] = memstatus.dwMemoryLoad;
    entropy[4] = sysinfo.dwNumberOfProcessors;
    entropy[5] = GetTickCount();
    entropy[6] = (unsigned long)((unsigned long long)GetModuleHandle(NULL) & 0xFFFFFFFF);
    entropy[7] = (unsigned long)((unsigned long long)entropy ^ 0xDEADBEEF);

    if (CryptAcquireContext((HCRYPTPROV*)&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash((HCRYPTPROV)provider, CALG_SHA_256, 0, 0, (HCRYPTHASH*)&hash)) {
            if (CryptHashData((HCRYPTHASH)hash, (unsigned char*)entropy, sizeof(entropy), 0)) {
                unsigned char fullhash[32];
                unsigned long hashsize = sizeof(fullhash);
                
                if (CryptGetHashParam((HCRYPTHASH)hash, HP_HASHVAL, fullhash, &hashsize, 0)) {
                    unsigned long copysize = (keysize <= hashsize) ? keysize : hashsize;
                    memcpy(key, fullhash, copysize);
                    success = 1;
                }
            }
            CryptDestroyHash((HCRYPTHASH)hash);
        }
        CryptReleaseContext((HCRYPTPROV)provider, 0);
    }

    return success;
}

void rc4_crypt(unsigned char* data, size_t datalen, unsigned char* key, size_t keylen) {
    unsigned char s[256];
    for (int i = 0; i < 256; i++) {
        s[i] = i;
    }

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + s[i] + key[i % keylen]) % 256;
        unsigned char temp = s[i];
        s[i] = s[j];
        s[j] = temp;
    }

    int i = 0;
    j = 0;
    for (size_t k = 0; k < datalen; k++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;

        unsigned char temp = s[i];
        s[i] = s[j];
        s[j] = temp;

        data[k] ^= s[(s[i] + s[j]) % 256];
    }
}
