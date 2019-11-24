# Sickle

Sickle is a payload development tool originally created to aid me in crafting shellcode, however it can be used in crafting payloads for other exploit types as well (non-binary). Although the current modules are mostly aimed towards assembly this tool is not limited to shellcode.

Sickle can aid in the following:
- Identifying instructions resulting in bad characters when crafting shellcode
- Formatting output in various languages (python, perl, javascript, etc).
- Accepting bytecode via STDIN and formatting it.
- Executing shellcode in both Windows and Linux environments.
- Diffing for two binaries (hexdump, raw, asm, byte)
- Dissembling shellcode into assembly language (ARM, x86, etc).
- Shellcode extraction from raw bins (nasm sc.asm -o sc)

### Quick failure check

A task I found myself doing repetitively was compiling assembler source code then extracting the shellcode, placing it into a wrapper, and testing it. If it was a bad run, the process would be repeated until successful. Sickle takes care of placing the shellcode into a wrapper for quick testing. (Works on Windows and Unix systems):

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/Documentation/pictures/r.png?style=centerme)

### Recreating shellcode

Sometimes you find a piece of shellcode that's fluent in its execution and you want to recreate it yourself to understand its underlying mechanisms. Sickle can help you compare the original shellcode to your "recreated" version.

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/Documentation/pictures/asm_compare.png?style=centerme)

If you're not crafting shellcode and just need 2 binfiles to be the same this feature can also help verifying files are the same byte by byte (multiple modes).

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/Documentation/pictures/hexdump_diff.png?style=centerme)

### Disassembly

Sickle can also take a binary file and convert the extracted opcodes (shellcode) to machine instructions. Keep in mind this works with raw opcodes (-r) and STDIN (-r -) as well. In the following example I am converting a reverse shell designed by Stephen Fewer to assembly.

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/Documentation/pictures/disassemble.png?style=centerme)

### Bad character identification

[![asciicast](https://asciinema.org/a/244211.svg)](https://asciinema.org/a/244211)

### Module Based Design

This tool was originally designed as a one big script, however recently when a change needed to be done to the script I had to relearn my own code... In order to avoid this in the future I've decided to keep all modules under the "modules" directory (default module: format). If you prefer the old design, I have kept a copy under the Documentation directory.


```
~# sickle.py -l

  Name                Description
  ----                -----------
  diff                Compare two binaries / shellcode(s). Supports hexdump, byte, raw, and asm modes
  run                 Execute shellcode on either windows or unix
  format              Format bytecode into desired format / language
  badchar             Generate bad characters in respective format
  disassemble         Disassemble bytecode in respective architecture
  pinpoint            Pinpoint where in shellcode bad characters occur

~# sickle -i -m diff
Options for diff

Options:

  Name        Required    Description
  ----        --------    -----------
  BINFILE     yes         Additional binary file needed to perform diff
  MODE        yes         hexdump, byte, raw, or asm

Description:

  Compare two binaries / shellcode(s). Supports hexdump, byte, raw, and asm modes

```
