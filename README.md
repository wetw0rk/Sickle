# Sickle

Sickle is a shellcode development tool created to speed up the various steps in creating a functioning payload. Although modules are aimed towards assembler, sickle is geared towards crafting payloads in various languages and is not limited to bytecode.

Sickle can aid in the following:
- Identifying instructions resulting in bad characters when crafting shellcode
- Formatting output in various languages (python, perl, javascript, etc).
- Accepting bytecode via STDIN and formatting it.
- Executing shellcode in both Windows and Linux environments.
- Comparing a bytecode sample to a modified binary.
- Dissembling shellcode into assembly language (ARM, x86, etc).
- Shellcode extraction via objdump (although binfiles never fail!)

### Quick failure check
A task I found myself doing repetitively was compiling assembler source code then extracting the shellcode, placing it into a wrapper, and testing it. If it was a bad run, the process would be repeated until successful. Sickle takes care of placing the shellcode into a wrapper for quick testing. (Works on Windows and Unix systems):

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/DOCUMENTATION/pictures/r.png?style=centerme)

### Recreating shellcode
Sometimes you find a piece of shellcode that's fluent in its execution and you want to recreate it yourself to understand its underlying mechanisms. Sickle can help you compare the original shellcode to your "recreated" version. If you're not crafting shellcode and just need 2 binfiles to be the same this feature can also help verifying files are the same byte by byte.

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/DOCUMENTATION/pictures/examine.png?style=centerme)

### Disassembly
Sickle can also take a binary file and convert the extracted opcodes (shellcode) to machine instructions. Keep in mind this works with raw opcodes (-r), object files (-obj), and STDIN (-s) as well. In the following example I am converting a reverse shell designed by Stephen Fewer to assembly.

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/DOCUMENTATION/pictures/disassemble.png?style=centerme)

### Bad character identification
It's important to note that currently bad character identification is best used within a Linux based operating system. When dumping shellcode on a Windows host bad characters will NOT be highlighted. 

[![asciicast](https://asciinema.org/a/244211.svg)](https://asciinema.org/a/244211)

### Module Based Design

This tool was originally designed during the CTP course (OSCE) as a one big script, however recently when a change needed to be done to the script I had to relearn my own code... In order to avoid this in the future I decided to keep all modules under the "modules" directory. I will be adding documentation on how to add your own formats and modules soon. If you prefer the old design, I have kept a copy under the DOCUMENTATION directory.

```sh
~# sickle -l
MODULE     	 DESCRIPTION                                                                     

pinpoint   	 pinpoint where in your shellcode bad characters occur                           
run        	 execute the shellcode on either windows or unix                                 
disassemble 	 disassemble bytecode in respective architecture                                 
compare    	 compare two binary files and view differences                                   

FORMAT     	 DESCRIPTION                                                                     

powershell 	 format bytecode for Powershell                                                  
uint8array 	 format bytecode for Javascript as a Uint8Array directly                         
python     	 format bytecode for Python                                                      
bash       	 format bytecode for bash script (UNIX)                                          
cs         	 format bytecode for C#                                                          
ruby       	 format bytecode for Ruby                                                        
nasm       	 format bytecode for NASM (useful for encoder stubs)                             
escaped    	 format bytecode for one-liner hex escape paste (e.g BB)                         
hex_space  	 format bytecode in hex, seperated by a space (e.g 65 77 77 74 72 30 00 6b)      
hex        	 format bytecode in hex (e.g 657777747230006b)                                   
perl       	 format bytecode for Perl                                                        
javascript 	 format bytecode for Javascript (neatly then into a Uint8Array)                  
python3    	 format bytecode for Python3 (minor changes to the language but they matter)     
dword      	 format bytecode in dword                                                        
c          	 format bytecode for a C (aka the best language in history)                      
java       	 format bytecode for Java (e.g (byte) 0xBE, (byte) 0xEF)                         
num        	 format bytecode in num format                                                   

ARCHITECTURES

x86_32
x86_64
mips32
mips64
arm
arm64
arm_thumb
```

### Windows Installation
If you decide to opt-out of the disassembly functions and only want to use Sickle as a wrapper/dumping tool Sickle will work out of the box with any Python version (Including 2.7). I have only encountered issues when writing/testing 64 bit shellcode on a Windows 10 host. In order to avoid problems I recommend installing [Python 3.4.4  (amd64)](https://www.python.org/ftp/python/3.4.4/python-3.4.4.amd64.msi) however any other Windows version should not have this issue. Should you be writing x86 shellcode, Windows 10 will work with any Python version e.g. [Python 3.7.0a3](https://www.python.org/ftp/python/3.7.0/python-3.7.0a3.exe).

### Linux Installation
Sickle is written in Python3 and to have full functionality I recommend installing [capstone](http://www.capstone-engine.org/) directly. If you don't need the disassembly function Sickle should work out of the box. Installation of Capstone is as easy as 1,2,3:
- apt-get install python3-pip
- pip3 install -r requirements.txt
- python3 setup.py install
    
If you don't compile your shellcode in NASM I have added an "[objdump2shellcode](https://github.com/wetw0rk/objdump2shellcode)" like function. Although I recommend using NASM for a streamline experience. If you use [Black Arch Linux](https://blackarch.org/index.html) Sickle comes pre-installed. (previously known as objdump2shellcode):

```sh
root@kali:~# sickle -h
usage: sickle.py [-h] [-r READ] [-f FORMAT] [-s] [-e EXAMINE] [-obj OBJDUMP]
                 [-m MODULE] [-a ARCH] [-b BADCHARS] [-v VARNAME] [-l]

Sickle - Payload development tool

optional arguments:
  -h, --help            show this help message and exit
  -r READ, --read READ  read bytes from binary file (any file)
  -f FORMAT, --format FORMAT
                        output format (--list for more info)
  -s, --stdin           read ops from stdin (EX: echo -ne "\xde\xad\xbe\xef" |
                        sickle -s -f <format> -b '\x00')
  -e EXAMINE, --examine EXAMINE
                        examine a separate file containing original shellcode.
                        mainly used to see if shellcode was recreated
                        successfully
  -obj OBJDUMP, --objdump OBJDUMP
                        binary to use for shellcode extraction (via objdump
                        method)
  -m MODULE, --module MODULE
                        development module
  -a ARCH, --arch ARCH  select architecture for disassembly
  -b BADCHARS, --badchars BADCHARS
                        bad characters to avoid in shellcode
  -v VARNAME, --varname VARNAME
                        alternative variable name
  -l, --list            list all available formats and arguments

```

