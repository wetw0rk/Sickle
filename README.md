# Sickle

Sickle is a shellcode development tool, created to speed up the various steps needed to create functioning shellcode. 

Sickle can aid in the following:
    - Identifying instructions resulting in bad characters
    - Format output in various languages (python, perl, javascript, etc)
    - Accept shellcode via stdin and format it / detect bad characters
    - Execute shellcode in both Windows and Linux environments
    - Compare reversed shellcode to original
    - Disassemble shellcode into assembly language (ARM, x86, etc)

#### Quick failure check
A task I found myself doing repetitively was compiling the ASM -> extracting shellcode -> placing it into a wrapper, and testing it. If it was a bad go, the process would be repeated until success. Sickle takes care of placing the shellcode into a wrapper for quick testing:

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/example-pictures/example.png?style=centerme)


#### Disassembly
Sickle can also take a binary file and convert the opcodes to machine instructions:

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/example-pictures/example2.png?style=centerme)

#### Recreating shellcode
Sometimes you find a piece of shellcode that is fluent in its execution and you want to recreate it yourself to understand its underlying mechanisms. Sickle can help you compare the original shellcode to your "recreated" version.

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/example-pictures/example3.png?style=centerme)

#### Bad character identification
It's important to note that currently bad character identification is best used within a Linux based OS. When dumping shellcode on Windows any bad characters will not be highlighted. Below is an example of usage in a Unix environment:

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/example-pictures/example4.png?style=centerme)

### Installation
Sickle is written in Python3 and to have full functionality I recommend installing [capstone](http://www.capstone-engine.org/), however at the moment the only "function" that requires capstone is disassembly. If you don't need the disassembly function Sickle should work out of the box. Installation of Capstone is as easy as 1,2,3:
    - apt-get install python3-pip
    - pip3 install capstone
    
Another thing to note is that if you do not compile your shellcode in NASM I have added an "[objdump2shellcode](https://github.com/wetw0rk/objdump2shellcode) like" function. Although I recommend using NASM for a streamline experience. For ease of access I prefer to add it to the /usr/bin/ directory like so:

```sh
root@wetw0rk:~# chmod +x sickle.py
root@wetw0rk:~# cp sickle.py /usr/bin/sickle
root@wetw0rk:~# sickle
usage: sickle [-h] [-r READ] [-s] [-obj OBJDUMP] [-f FORMAT] [-b BADCHAR]
              [-v VARNAME] [-l] [-e EXAMINE] [-d] [-a ARCH] [-m MODE] [-rs]

Sickle - a shellcode development tool

optional arguments:
  -h, --help            show this help message and exit
  -r READ, --read READ  Read byte array from the binary file
  -s, --stdin           read ops from stdin (EX: echo -ne "\xde\xad\xbe\xef" |
                        sickle -s -f <format> -b '\x00')
  -obj OBJDUMP, --objdump OBJDUMP
                        binary to use for shellcode extraction (via objdump
                        method)
  -f FORMAT, --format FORMAT
                        Output format (use --list for a list)
  -b BADCHAR, --badchar BADCHAR
                        Bad characters to avoid in shellcode
  -v VARNAME, --varname VARNAME
                        alternative variable name
  -l, --list            List all available formats and arguments
  -e EXAMINE, --examine EXAMINE
                        Examine a separate file containing original shellcode.
                        Mainly used to see if shellcode was recreated
                        successfully
  -d, --disassemble     disassemble the binary file
  -a ARCH, --arch ARCH  select architecture for disassembly
  -m MODE, --mode MODE  select mode for disassembly
  -rs, --run-shellcode  run the shellcode (on linux generates binary)
```

