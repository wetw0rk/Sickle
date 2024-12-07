# Sickle

![alt text](./docs/logo/panda_logo.png)

Sickle is a tool I originally developed to help me be more effective, in both developing and understanding shellcode. However, throughout the course of its development and usage It has evolved into a payload development framework. Although current modules are mostly aimed towards assembly, this tool is not limited to shellcode.

Currently sickle can assist in the following.

- Shellcode Generation
- Diffing
- Bad Character Identification
- Shellcode Execution
- Disassembly
- Shellcode Extraction

**WARNING**: Sickle is currently undergoing massive changes to support shellcode generation. For a stable version, please use the latest release.

## Shellcode Generation

Sickle supports shellcode generation via the [Keystone Engine](https://www.keystone-engine.org/). Due to this being a newly added feature, payload support is limited.

![alt text](./docs/screenshots/generation.gif)

## Diffing

This functionality of sickle was originally implemented to aid me in understanding public shellcode stubs. When assembly diffing is performed the diff will occur on both the assembly and opcode level individually.

![alt text](./docs/screenshots/diff_shellcode.png)

Additionally, sickle supports multiple modes in which to perform the diff and can be useful even outside of shellcode development. Notably sickle currently supports both Windows and Linux for all modules not just diffing.

![alt text](./docs/screenshots/hexdump_diff.png)

## Shellcode Execution

A task you may find yourself doing repeatedly is testing your shellcode. These steps normally involve:

1. Compiling assembly language
2. Extracting shellcode into the proper format for your respective wrapper
3. Compiling the wrapper
4. Executing it

Although these steps may not seem like a lot they add up when you do them over and over until you get your expected outcome. Sickle takes care of placing the shellcode into a wrapper for quick testing and works on both Windows and Unix systems.

![alt text](./docs/screenshots/r.png)

## Disassembly

Sickle can also take a binary file and convert the extracted opcodes (shellcode) to machine instructions (assembly). Keep in mind this works with raw binary only and disassembly is currently only done in a linear fashion.

![alt text](./docs/screenshots/disassemble.png)

Shown above the module disassembles a reverse shell designed by Stephen Fewer to assembly.

## Shellcode Extraction

Shellcode extraction was the first module or rather functionality for sickle as opcodes are interpreted differently depending on the wrapper you are using. You cannot expect JavaScript to store and interpret shellcode the same way a C program would.

![alt text](./docs/gifs/format.gif)

Perhaps the biggest inspiration for this was `msfvenom`.

## Bad Character Identification

Although not prevalent in 64bit exploits there may be times an exploit restricts certain characters from being used. This is where the pinpoint module shines as it directly shows the assembly instructions responsible for the identified bad character.

![alt text](./docs/gifs/pinpoint.gif)

# Module Based Design

This tool was originally designed as a one big script, however as the tool evolved, I found myself needing to re-learn my code every update. As such, sickle now follows a modular approach with the goal being to implement new functionality as needed with minimal time spent re-learning sickles design.

```
$ sickle -l

  Shellcode                                                                        Description
  ---------                                                                        -----------
  windows/x64/kernel_token_stealer                                                 Kernel token stealing shellcode (Windows x64)
  windows/x64/kernel_sysret                                                        Kernel shellcode for returning to user-mode from kernel-mode
  windows/x64/kernel_ace_edit                                                      Kernel shellcode to modify the _SECURITY_DESCRIPTOR of a process
  windows/x64/shell_reverse_tcp                                                    TCP based reverse shell over IPV4 which returns an interactive cmd.exe session
  windows/x86/kernel_token_stealer                                                 Kernel token stealing shellcode (Windows x86)
  linux/aarch64/shell_reverse_tcp                                                  TCP based reverse shell over IPV4 which returns an interactive /bin/sh session (Linux AARCH64)
  linux/x86/shell_reverse_tcp                                                      TCP based reverse shell over IPV4 which returns an interactive /bin/sh session (Linux x86)

  Modules             Description
  -------             -----------
  asm_shell           Interactive assembler and disassembler
  disassemble         Simple linear disassembler for multiple architectures
  diff                Bytecode diffing too for comparing two binaries (or shellcode)
  format              Converts bytecode into a respective format
  run                 Wrapper used for executing bytecode
  badchar             Generates bad characters for bad character validation
  pinpoint            Highlight bad characters within a disassembly to id bad characters

  Format              Description
  ------              -----------
  c                   Format bytecode for a C application
  java                Format bytecode for Java
  hex                 Format bytecode in hex
  num                 Format bytecode in num format
  powershell          Format bytecode for Powershell
  bash                Format bytecode for bash script (UNIX)
  nasm                Format bytecode for NASM
  raw                 Format bytecode to be written to stdout in raw form
  python3             Format bytecode for Python3
  cs                  Format bytecode for C#
  python              Format bytecode for Python
  uint8array          Format bytecode for Javascript as a Uint8Array directly
  hex_space           Format bytecode in hex, seperated by a space
  dword               Format bytecode in dword
  escaped             Format bytecode for one-liner hex escape paste
  javascript          Format bytecode for Javascript (Blob to send via XHR)
  perl                Format bytecode for Perl
  ruby                Format bytecode for Ruby
```

Allowing for a way to self-document each functionality provided by respective modules.

```
$ sickle -i -m run                            

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

Description:
    
    Executes bytecode from a binary file (-r) or a payload module (-p) under the
    context of the currently running operating system and architecture. Meaning if
    you are running on AARCH64 bytecode will be interpreted as such and if your on
    x64 it will interpret it as x64 respectively.
    
Example:

    sickle.py -m run -r shellcode
```


This also includes shellcode stubs.

```
$ sickle -i -p linux/aarch64/shell_reverse_tcp

Usage information for linux/aarch64/shell_reverse_tcp

              Name: Linux (AARCH64 or ARM64) SH Reverse Shell
            Module: linux/aarch64/shell_reverse_tcp
      Architecture: aarch64
          Platform: Linux
              Ring: 3

Author(s):
    wetw0rk

Tested against:
    Kali Linux

Argument Information

  Argument Name        Argument Description                               Optional
  -------------        --------------------                               --------
  LHOST                Listener host to receive the callback              no
  LPORT                Listening port on listener host                    yes

Description:
    
    Simple reverse shellcode that will spawn a connection back to a listening tcp
    server. Connection is made via TCP over IPV4.
    
Example:

    sickle.py -p linux/aarch64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=1337 -f c
```
