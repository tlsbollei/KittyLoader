#include "api_resolver.h"

DWORD compute_custom_hash(const char* str) {
    DWORD hash = 0xDEADBEEF;
    while (*str) {
        hash = (hash >> 3) | (hash << 29);
        hash ^= *str++;
        hash += 0x55555555;
    }
    return hash;
}

PVOID get_function_by_hash(HMODULE module, DWORD hash) {
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)module + dos_header->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY export_dir = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* functions = (DWORD*)((BYTE*)module + export_dir->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)module + export_dir->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)module + export_dir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < export_dir->NumberOfNames; i++) {
        const char* name = (const char*)module + names[i];
        if (compute_custom_hash(name) == hash) {
            return (PVOID)((BYTE*)module + functions[ordinals[i]]);
        }
    }
    return NULL;
}