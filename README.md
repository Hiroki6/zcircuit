# zcircuit

Short-circuiting the Windows API for direct syscall execution.

This is a Zig library designed for direct syscall exeuction by dynamically resolving System Service Numbers (SSNs) and executing syscalls through legitimate memory instructions.

# Features

- Hell's Gate: Dynamic SSN resolution by parsing ntdll.dll Export Address Table.
- TartarusGate: Neighboring syscall analysis to recover SSNs when a target function is hooked.
- Hell's Hall: Indirect syscall execution by searching for clean syscall; ret gadgets in ntdll memory to bypass instruction-level monitoring.
- Comptime Stealth: * CRC32 Hashing: Function names are hashed at compile-time with a user-configurable seed. No sensitive strings remain in the binary.

# Quick Start

See the [example](./example/).

```powershell
> inject_shellcode.exe
[+] Resolved NtAllocateVirtualMemory -> SSN: 0x18, Base: 0x7FFE4410D9A2
[+] Memory allocated at: 0x26afad10000
[+] Resolved NtProtectVirtualMemory -> SSN: 0x50, Base: 0x7FFE4410E0A2
[+] Memory protected!
[+] Resolved NtCreateThreadEx -> SSN: 0xC2, Base: 0x7FFE4410EED2
[+] Thread created!
[+] Resolved NtWaitForSingleObject -> SSN: 0x04, Base: 0x7FFE4410D722
```

# Credits & Inspiration
This project is a Zig implementation and refinement of several pioneering research techniques.

- [Hell's Gate](https://github.com/am0nsec/HellsGate): The original technique for dynamic SSN extraction.
- [TartarusGate](https://github.com/trickster0/TartarusGate): Improved SSN recovery via neighboring stubs.
- [Hell's Hall](https://github.com/Maldev-Academy/HellHall): Indirect syscall instruction searching.
- [Bananaphone](https://github.com/C-Sto/BananaPhone): A major inspiration for the API design.

# Legal Disclaimer

This tool is for educational purposes and authorized security auditing only. The author is not responsible for any misuse of this software.