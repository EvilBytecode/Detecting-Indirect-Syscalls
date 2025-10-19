# Indirect Syscall Detector

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows-0078d4.svg)](https://www.microsoft.com/windows)
[![Language](https://img.shields.io/badge/language-C%2B%2B-00599c.svg)](https://isocpp.org/)
[![Architecture](https://img.shields.io/badge/arch-x64-red.svg)](https://en.wikipedia.org/wiki/X86-64)

Detection of indirect syscall techniques using hardware breakpoints and vectored exception handling.
- shoutout to : https://xacone.github.io/mitigate-indirect-syscalls.html
---

## Overview

Indirect Syscall Detector is a Windows security tool designed to monitor and detect indirect syscall invocations in real-time. The tool operates by placing hardware breakpoints on specific syscall instructions within ntdll.dll and validating the return address on the stack against a whitelist of trusted system modules.

### Indirect Syscalls Explained

Indirect syscalls are a technique used to evade user-mode hooks placed by security products. The technique works as follows:

1. The attacker locates the `syscall` instruction within ntdll.dll functions
2. The syscall number and instruction address are extracted
3. Custom shellcode is created that directly invokes the syscall instruction
4. The syscall executes from untrusted memory, bypassing hooks on the function prologue

This technique is effective because most EDR/AV products hook the beginning of NT API functions in ntdll.dll, but the actual syscall instruction remains unhooked. By jumping directly to the syscall instruction from custom code, the hooks are never triggered.

### Detection Methodology

This tool detects indirect syscalls by monitoring the return address when a syscall instruction executes. Legitimate calls to NT APIs will have a return address pointing back into ntdll.dll or other trusted system modules. Indirect syscalls will have a return address pointing to untrusted memory regions (heap, stack, or custom allocations).

The detection mechanism:
1. Hardware breakpoints (DR0-DR3) are set on syscall instructions
2. When a breakpoint hits, a Vectored Exception Handler (VEH) captures the exception
3. The return address is read from RSP (stack pointer)
4. The return address is validated against trusted module address ranges
5. If the return address is outside trusted ranges, an alert is generated

---

## Technical Details

### Hardware Breakpoints

The tool utilizes the x64 debug registers for detection:
- **DR0-DR3**: Store addresses of up to 4 syscall instructions to monitor
- **DR7**: Control register that enables/configures the breakpoints

Hardware breakpoints are configured for execution breakpoints on 1-byte boundaries, causing a single-step exception (EXCEPTION_SINGLE_STEP) when the monitored syscall instruction executes.

### Vectored Exception Handler

A VEH is registered to intercept single-step exceptions. The handler performs the following operations:

1. Validates the exception occurred at one of the monitored syscall addresses
2. Reads the return address from the stack (RSP register)
3. Checks if the return address falls within a trusted module's address range
4. Logs the event if the return address is untrusted
5. Temporarily disables hardware breakpoints and enables trap flag (EFLAGS.TF)
6. After one instruction, re-enables hardware breakpoints

This single-step mechanism is necessary to avoid infinite loops, as the breakpoint would continuously trigger on the same instruction.

### Trusted Module Ranges

The detector builds a table of trusted memory ranges by parsing the export tables of system DLLs. By default, only ntdll.dll is trusted, but this can be expanded to include:
- kernel32.dll / kernelbase.dll
- user32.dll / gdi32.dll
- advapi32.dll

Each exported function from these modules is recorded as a trusted range (function address + 0x100 bytes).

### Thread Instrumentation

All threads in the target process must be instrumented with hardware breakpoints. The tool:
1. Enumerates all threads using CreateToolhelp32Snapshot
2. Opens each thread with NtOpenThread
3. Suspends the thread with NtSuspendThread (if not the current thread)
4. Retrieves the thread context with NtGetContextThread
5. Modifies DR0-DR3 and DR7 to set breakpoints
6. Restores the thread context with NtSetContextThread
7. Resumes the thread with NtResumeThread

A secondary scan is performed after initialization to catch newly created threads.

---

## Architecture Support

This tool is designed exclusively for x64 (64-bit) Windows systems. The following considerations apply:

## Trusted Module Bypass
If an attacker can execute code from within a trusted module's address space (e.g., via ROP chains), the detection can be bypassed as the return address would appear legitimate.

## Resources

- [Windows Internals, Part 1 (7th Edition)](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals) - Deep dive into Windows architecture
- [Intel 64 and IA-32 Architectures Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) - Debug register documentation
- [Vectored Exception Handling](https://docs.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling) - VEH implementation details
- [Hell's Gate](https://github.com/am0nsec/HellsGate) - Original indirect syscall research
- [SysWhispers](https://github.com/jthuraisamy/SysWhispers) - Syscall technique framework

---

## License

MIT License

Copyright (c) 2025

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
