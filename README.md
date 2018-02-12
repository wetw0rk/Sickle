# Sickle

Sickle is a shellcode development tool created to speed up the various steps needed to create functioning shellcode. 

Sickle can aid in the following:
- Identifying instructions resulting in bad characters.
- Formatting output in various languages (python, perl, javascript, etc).
- Accepting shellcode via STDIN and formatting it.
- Executing shellcode in both Windows and Linux environments.
- Comparing reversed shellcode to original.
- Dissembling shellcode into assembly language (ARM, x86, etc).

#### Quick failure check
A task I found myself doing repetitively was compiling assembly source code then extracting the shellcode, placing it into a wrapper, and testing it. If it was a bad run, the process would be repeated until successful. Sickle takes care of placing the shellcode into a wrapper for quick testing. (Works on Windows and Unix systems):

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/example-pictures/r.png?style=centerme)

#### Recreating shellcode
Sometimes you find a piece of shellcode that's fluent in its execution and you want to recreate it yourself to understand its underlying mechanisms. Sickle can help you compare the original shellcode to your "recreated" version.

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/example-pictures/c.png?style=centerme)

#### Bad character identification
It's important to note that currently bad character identification is best used within a Linux based operating system. When dumping shellcode on a Windows host bad characters will not be highlighted. Below is a usage example in a Unix environment:

[![asciicast](https://asciinema.org/a/7vvVRjZGbY7OlqMsh6dBi7FDU.png)](https://asciinema.org/a/7vvVRjZGbY7OlqMsh6dBi7FDU)

#### Disassembly
Sickle can also take a binary file and convert the extracted opcodes (shellcode) to machine instructions (-obj). Keep in mind this works with raw opcodes (-r) and STDIN (-s) as well. In the following example I am converting a reverse shell designed by Stephen Fewer to assembly.

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/example-pictures/d.png?style=centerme)

### Windows Installation
If you decide to opt-out of the disassembly functions and only want to use Sickle as a wrapper/dumping tool Sickle will work out of the box with any Python version (Including 2.7). I have only encountered issues when writing/testing 64 bit shellcode on a Windows 10 host. In order to avoid problems I recommend installing [Python 3.4.4  (amd64)](https://www.python.org/ftp/python/3.4.4/python-3.4.4.amd64.msi) however any other Windows version should not have this issue. Should you be writing x86 shellcode, Windows 10 will work with any Python version eg [Python 3.7.0a3](https://www.python.org/ftp/python/3.7.0/python-3.7.0a3.exe). Below is a usage example testing msfvenom generated shellcode ("windows/x64/shell_reverse_tcp") on a Windows 10 host

![alt text](https://raw.githubusercontent.com/wetw0rk/Sickle/master/example-pictures/Win10.png?style=centerme)

### Linux Installation
Sickle is written in Python3 and to have full functionality I recommend installing [capstone](http://www.capstone-engine.org/) directly. If you don't need the disassembly function Sickle should work out of the box. Installation of Capstone is as easy as 1,2,3:
- apt-get install python3-pip
- pip3 install capstone
    
If you don't compile your shellcode in NASM I have added an "[objdump2shellcode](https://github.com/wetw0rk/objdump2shellcode)" like function. Although I recommend using NASM for a streamline experience. For ease of access I prefer to add Sickle to the /usr/bin/ directory however if you use [Black Arch Linux](https://blackarch.org/index.html) Sickle comes pre-installed. (previously known as objdump2shellcode):

```sh
root@kali:~# git clone https://github.com/wetw0rk/Sickle.git
root@kali:~# cd Sickle/
root@kali:~# chmod +x sickle.py
root@kali:~# cp sickle.py /usr/bin/sickle
root@kali:~# sickle 
usage: sickle [-h] [-r READ] [-s] [-obj OBJDUMP] [-f FORMAT] [-b BADCHAR] [-c]
              [-v VARNAME] [-l] [-e EXAMINE] [-d] [-rs] [-a ARCH] [-m MODE]

Sickle - Shellcode development tool

optional arguments:
  -h, --help            show this help message and exit
  -r READ, --read READ  read byte array from the binary file
  -s, --stdin           read ops from stdin (EX: echo -ne "\xde\xad\xbe\xef" |
                        sickle -s -f <format> -b '\x00')
  -obj OBJDUMP, --objdump OBJDUMP
                        binary to use for shellcode extraction (via objdump
                        method)
  -f FORMAT, --format FORMAT
                        output format (use --list for a list)
  -b BADCHAR, --badchar BADCHAR
                        bad characters to avoid in shellcode
  -c, --comment         comments the shellcode output
  -v VARNAME, --varname VARNAME
                        alternative variable name
  -l, --list            list all available formats and arguments
  -e EXAMINE, --examine EXAMINE
                        examine a separate file containing original shellcode.
                        mainly used to see if shellcode was recreated
                        successfully
  -d, --disassemble     disassemble the binary file
  -rs, --run-shellcode  run the shellcode (use at your own risk)
  -a ARCH, --arch ARCH  select architecture for disassembly
  -m MODE, --mode MODE  select mode for disassembly
```

