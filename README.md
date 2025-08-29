
# KittyLoader
### About
KittyLoader is a highly evasive loader written in C / Assembly.

### Features
- Hijacks early execution by replacing the C runtime entrypoint (__scrt_common_main_seh) with custom assembly.
  
- Hides all modules by walking PEB->Ldr lists and unlinking its module entry (LDR_DATA_TABLE_ENTRY) from :
    - InLoadOrderModuleList
    - InInitializationOrderModuleList
    - InMemoryOrderModuleList
      
- Deploys a wide variety of anti-analysis techniques, including :
    - Debugger Detection :
          - IsDebuggerPresent, CheckRemoteDebuggerPresent, PEB Interrogation, hardware breakpoints, timing checks (RDTSC + Sleep) using             __rdtsc timing analysis
    - Sandbox Detection :
          - Heuristic evaluation of sandbox probability from > GetSystemInfo, GlobalMemoryStatusEx, GetDiskFreeSpaceEx, GetTickCount
    - Self-Integrity checks by continously calculating checksum of its own code section to detect tampering.
    - Delayed Execution :
          - Sleeps for 30–40 seconds plus jitter based on PID and system tick count.

- API Resolution via Export Hashing :
    - Avoids static imports by resolving function addresses at runtime.
    - Walks IMAGE_EXPORT_DIRECTORY and applies custom xor rotate hash algo.
    - APIs are initially attempted to be resolved via tprtdll.dll, which is quite the modern technique, it does so using GetModuleHandleW(L"tprtdll.dll") with DONT_RESOLVE_DLL_REFERENCES to minimize operation footprint.
 
  
- Embedded payload is encrypted at rest, with key and nonce derived at runtime from entropy sources: PID, TID, QPC, memory load, CPU info (CPUID), tick count.
- Preferred algo is ChaCha20, but in case of failure falls back to RC4, decryption occurs in place after the encrypted blob is copied into memory.

- Searches process memory via VirtualQuery for an already-executable region large enough for the shellcode.
    - If none found, allocates new RW region with NtAllocateVirtualMemoryEx
    - After decryption, if memory was RW, flips to RX with NtProtectVirtualMemory.
    - Therefore, we intend to initially inject into pre-existing RWX memory page, but in case of failure, resort to custom resolved NtAllocateVirtualMemoryEx and flip RW-RX

- Execute via LdrCallEnclave, normally intended for SGX/VBS enclaves, instead of jumping to a secure enclave, we jump to an arbitrary function pointer in normal (VTL0) user memory.


![Preview](https://pbs.twimg.com/media/FHe1LP-X0AoPxav?format=png&name=medium)

### Credits:
- [@whokilleddb](https://x.com/whokilleddb): [Run shellcode using LdrCallEnclave](https://gist.github.com/whokilleddb/ef1f8c33947f6ceb90664ce38d3dcf04)
- [trickster0](https://twitter.com/trickster012) [TartarusGate](https://github.com/trickster0/TartarusGate/) direct syscall method
- [@whokilleddb](https://x.com/whokilleddb): [tprtdll.dll (like so many others) exposes some Nt/Rtl/Zw functions, without redirecting to the ntdll.dll!](https://github.com/whokilleddb/function-collections/blob/main/winapi_alternatives/NtAllocateMemoryEx/main.c)
