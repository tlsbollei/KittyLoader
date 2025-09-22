#include "api_resolver.h"

unsigned long hashstr(const char* s) {
    unsigned long hash = 0xDEADBEEF;
    while (*s) {
        hash = (hash >> 3) | (hash << 29);
        hash ^= *s++;
        hash += 0x55555555;
    }
    return hash;
}

void* findfunc(void* module, unsigned long hash) {
    auto dos = (IMAGE_DOS_HEADER*)module;
    auto nt = (IMAGE_NT_HEADERS*)((char*)module + dos->e_lfanew);
    auto exportdir = (IMAGE_EXPORT_DIRECTORY*)((char*)module + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    unsigned long* functions = (unsigned long*)((char*)module + exportdir->AddressOfFunctions);
    unsigned long* names = (unsigned long*)((char*)module + exportdir->AddressOfNames);
    unsigned short* ordinals = (unsigned short*)((char*)module + exportdir->AddressOfNameOrdinals);

    for (unsigned long i = 0; i < exportdir->NumberOfNames; i++) {
        const char* name = (const char*)module + names[i];
        if (hashstr(name) == hash) {
            return (void*)((char*)module + functions[ordinals[i]]);
        }
    }
    return NULL;
}
