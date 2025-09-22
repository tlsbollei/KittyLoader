#pragma once
#include <windows.h>

int makechacha(unsigned char* key, unsigned long keysize, unsigned char* nonce, unsigned long noncesize);
void chacha_crypt(unsigned char* data, size_t datalen, unsigned char* key, size_t keylen, unsigned char* nonce);
int makekey(unsigned char* key, unsigned long keysize);
void rc4_crypt(unsigned char* data, size_t datalen, unsigned char* key, size_t keylen);
