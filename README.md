# Sickle

![alt text](./docs/logo/sickle-hallow-2025.png)

Sickle is a tool I originally developed to help me be more effective, in both developing and understanding shellcode. However, throughout the course of its development and usage It has evolved into a payload development framework. Although current modules are mostly aimed towards assembly, this tool is not limited to shellcode.

Currently sickle can assist in the following.

- Converting assembly instructions to machine code (opcodes)
- Executing bytecode, including generated payloads
- Formatting opcodes for a target language
- Bad character identification
- Linear disassembly
- Diffing

## Shellcode Generation

Sickle supports shellcode generation via the [Keystone Engine](https://www.keystone-engine.org/). Due to this being a newly added feature, payload support is limited. However, the goal is to add a basic reverse shell for each architecture and platform.

![alt text](./docs/screenshots/generation.gif)

## Diffing

Sickle includes a "diffing" module initially designed for analyzing shellcode stubs. The original "asm" mode performs linear disassembly diffs at both the assembly language and opcode levels separately.

![alt text](./docs/screenshots/diff_shellcode.png)

In addition, Sickle offers various modes for performing diffs, making it useful beyond shellcode development.

![alt text](./docs/screenshots/hexdump_diff.png)

## Shellcode Execution

One common task you may often perform is testing your shellcode. This process typically involves the following steps:

1. Compile the assembly language code.
2. Extract the shellcode and format it appropriately for your chosen wrapper.
3. Compile the wrapper.
4. Execute the wrapper.

Although these steps may seem minor, they can become time-consuming when done repeatedly. Sickle simplifies the process by automatically wrapping shellcode for quick testing, and the "run" module currently supports both Windows and Unix systems.

![alt text](./docs/screenshots/r.png)

## Disassembly

Sickle can also convert a binary file into extracted opcodes (shellcode) and then translate those into machine instructions (assembly). Note that this process only works with raw binary files and currently performs disassembly in a linear fashion via [Capstone](https://www.capstone-engine.org/).

![alt text](./docs/screenshots/disassemble.png)

In the example shown above the "disassemble" module disassembles a reverse shell designed by Stephen Fewer to assembly.

## Shellcode Extraction

Shellcode extraction was the first module, or rather, the core functionality for Sickle, as opcodes are interpreted differently depending on the wrapper used. JavaScript, for example, does not store and interpret shellcode in the same way as a C program would.

![alt text](./docs/gifs/format.gif)

Perhaps the biggest inspiration for this was `msfvenom`.

## Bad Character Identification

Although less common in 64-bit exploits, there may be instances where an exploit restricts the use of certain characters. This is where the "pinpoint" module excels, as it directly identifies and highlights the assembly instructions responsible for the identified bad character(s).

![alt text](./docs/gifs/pinpoint.gif)

# Module Based Design

Originally, this tool started as a single large script. However, as it evolved, I found myself needing to re-learn the code with each update. To address this, Sickle now follows a modular approach, allowing for new functionality to be added with minimal time spent re-learning the tool’s design.

```
sickle.py -l

  Shellcode                              Ring Description
  ---------                              ---- -----------
  linux/x86/shell_reverse_tcp             3   Reverse shell via TCP over IPV4 that provides an interactive /bin/sh session
  linux/aarch64/shell_reverse_tcp         3   Reverse Shell via TCP over IPv4 that provides an interactive /bin/sh session
  linux/aarch64/memfd_reflective_elf_tcp  3   Staged Reflective ELF Loader via TCP over IPv4 which executes an ELF from a remote server handler
  linux/x64/memfd_reflective_elf_tcp      3   Staged Reflective ELF Loader via TCP over IPV4 which executes an ELF from a remote server
  windows/x86/shell_reverse_tcp           3   Reverse shell via TCP over IPv4 that provides an interactive cmd.exe session
  windows/aarch64/shell_reverse_tcp       3   Reverse Shell via TCP over IPv4 that provides an interactive cmd.exe session
  windows/x64/virtualalloc_exec_https     3   A lightweight stager that connects to a handler over HTTPS to receive and execute shellcode
  windows/x64/shell_reverse_tcp           3   Reverse Shell via TCP over IPv4 that provides an interactive cmd.exe session
  windows/x64/reflective_pe_loader        3   Stageless Reflective PE Loader that takes an x64 binary and executes it in memory
  windows/x64/virtualalloc_exec_tcp       3   A lightweight stager that connects to a handler via TCP over IPv4 to receive and execute shellcode
  windows/x64/exec                        3   Executes a command on the target host
  windows/x64/egghunter                   3   Egghunter based on Hell's Gate and NtProtectVirtualMemory
  windows/x64/old_process_injection       3   Process injection using embedded 2nd stage shellcode
  windows/x86/kernel_token_stealer        0   Token stealing shellcode for privilege escalation
  windows/x64/kernel_token_stealer        0   Token stealing shellcode for privilege escalation
  windows/x64/kernel_sysret               0   Generic method of returning from kernel space to user space
  windows/x64/kernel_ace_edit             0   SID entry modifier for process injection

  Architectures
  -------------
  aarch64
  x64
  x86

  Modules       Description
  -------       -----------
  asm_shell     Interactive assembler and disassembler
  run           Wrapper used for executing bytecode (shellcode)
  badchar       Produces a set of all potential invalid characters for validation purposes
  diff          Bytecode diffing module for comparing two binaries (or shellcode)
  handler       Module for handling payload distribution and session management
  disassemble   Simple linear disassembler for multiple architectures
  pinpoint      Highlights opcodes within a disassembly to identify instructions responsible for bad characters
  format        Converts bytecode into a respective format (activated anytime '-f' is used)

  Format        Description
  ------        -----------
  python        Format bytecode for Python
  num           Format bytecode in num format
  java          Format bytecode for Java
  rust          Format bytecode for a Rust application
  hex_space     Format bytecode in hex, seperated by a space
  c             Format bytecode for a C application
  python3       Format bytecode for Python3
  bash          Format bytecode for bash script (UNIX)
  raw           Format bytecode to be written to stdout in raw form
  hex           Format bytecode in hex
  javascript    Format bytecode for Javascript (Blob to send via XHR)
  powershell    Format bytecode for Powershell
  uint8array    Format bytecode for Javascript as a Uint8Array directly
  escaped       Format bytecode for one-liner hex escape paste
  cs            Format bytecode for C#
  perl          Format bytecode for Perl
  nasm          Format bytecode for NASM
  dword         Format bytecode in dword
  ruby          Format bytecode for Ruby
```

This approach allows each module the ability to generate detailed documentation for its functionality.

```
$ sickle -m run -i

Usage information for run

              Name: Shellcode Runner
            Module: run
      Architecture: Multi
          Platform: Multi
              Ring: 3

Author(s):
    wetw0rk

Tested against:
    Linux
    Windows

Module Description:

  Executes bytecode from a binary file (-r) or a payload module (-p) under the context
  of the currently running operating system and architecture. Meaning if you are
  running on AARCH64 bytecode will be interpreted as such and if you're on x64 it will
  interpret it as x64 respectively.

Example:

  /usr/local/bin/sickle -m run -r shellcode
```

This approach also includes documentation for shellcode stubs.

```
$ sickle -p windows/x64/egghunter -i

Usage information for windows/x64/egghunter

              Name: Windows (x64) Hell's Gate based Egghunter
            Module: windows/x64/egghunter
      Architecture: x64
          Platform: windows
              Ring: 3

Author(s):
    hvictor

Tested against:
    Windows 11 (10.0.26100 N/A Build 26100)

Argument Information

  Name          Description           Optional
  ----          -----------           --------
  TAG           Egg (provide 4 bytes)      yes

Module Description:

  This egghunter iterates virtual memory addresses and before searching for the egg, it
  performs a NtProtectVirtualMemory system call. This system call is similar to
  VirtualProtect, and is parameterized to set the memory to be scanned to READ, WRITE,
  EXECUTE. This way, when the egg is found, the shellcode after it is guaranteed to be
  executable.

Example:

  /usr/local/bin/sickle -p windows/x64/egghunter TAG=w00t
```
