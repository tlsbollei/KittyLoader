<p style="text-align:center;">
  <em>« La force se cache dans l’invisible, et l’invisible gouverne tout. »</em>
</p>

<div style="text-align:center; margin-top:8px;">
  <img src="asset/charles-chevalier.jpg"
       alt="Charles Chevalier (Blue Lock)"
       width="400">
</div>

# KittyLoader
![GitHub Stars](https://img.shields.io/github/stars/tlsbollei/KittyLoader?style=social&logo=github)
![GitHub Repo forks](https://img.shields.io/github/forks/tlsbollei/KittyLoader?style=social&logo=github)


> [!CAUTION]
> **Disclaimer & Legal Notice**  
> This repository, **KittyLoader**, and all associated code, techniques, and information are provided strictly for **educational and academic research purposes**.  
>
> This sample and its methodologies have been **proactively disclosed to relevant cybersecurity defense organizations and vendors**. It is actively used by defensive engineers to research attack patterns, develop detection capabilities, and enhance security products.  
>
> You are required to use this knowledge and these tools **only on systems you own or have explicit, written permission to test**.  
> Any unauthorized use against systems you do not own is **illegal and strictly prohibited**.  
>
> This tool was created to advance the field of defensive cybersecurity. The author, *tlsbollei*, assumes **no liability** and is not responsible for any misuse or damage caused by this software.  
>
> By accessing this repository, you acknowledge that you understand its purpose is to learn about **modern malware techniques, evasion tactics**, and ultimately to **improve our collective ability to defend against them**.


By proceeding, you agree to use this information responsibly and legally.


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


<img src="asset/proof.PNG" alt="" width="950">

### Credits:
- [@whokilleddb](https://x.com/whokilleddb): [Run shellcode using LdrCallEnclave](https://gist.github.com/whokilleddb/ef1f8c33947f6ceb90664ce38d3dcf04)
- [trickster0](https://twitter.com/trickster012) [TartarusGate](https://github.com/trickster0/TartarusGate/) direct syscall method
- [@whokilleddb](https://x.com/whokilleddb): [tprtdll.dll (like so many others) exposes some Nt/Rtl/Zw functions, without redirecting to the ntdll.dll!](https://github.com/whokilleddb/function-collections/blob/main/winapi_alternatives/NtAllocateMemoryEx/main.c)
