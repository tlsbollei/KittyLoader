#pragma once
#include <windows.h>

typedef long (__stdcall* _allocmem)(
    void* process,
    void** addr,
    unsigned long long* size,
    unsigned long alloctype,
    unsigned long protect,
    void* extra,
    unsigned long extracount);

typedef long (__stdcall* _protectmem)(
    void* process,
    void** addr,
    unsigned long long* size,
    unsigned long newprotect,
    unsigned long* oldprotect);

typedef long (__stdcall* _callfunc)(
    void* func,
    unsigned long flags,
    void** result);

void* findmem(size_t size);
void* gettargetmod();
void runpayload();

extern unsigned char shellbytes[];
extern size_t shellsize;