# Sickle Documentation

Crafting your own modules for sickle or adding a new format is simple. This design was recently re-implemented to avoid constant updates to the main program. I plan on adding a seperate payload directory soon to support custom payload stubs crafted by you. 

## Sickle functions

The two main scripts you'll see called by the modules can be found within the `common/lib` directory (`extract` and `pcolors`).

### Extract

This script contains 2 main functions `analysis` and `standard_bin`.

#### Extract - standard_bin

The standard_bin function will parse a file and return 3 objects, depending on the argument (True or False) the second object will either be raw or escaped. Below are the return objects that can be referenced like a list.

1. filename
2. raw bytecode or escaped bytecode
3. size of the binary / bytes

The function definition is shown below:

```
standard_bin(dump_src, raw)
```

#### Extract - analysis

 The analysis function will parse and opcode escaped string in search of bad characters and return the bad bytes in red. When using this function there are 3 arguments passed to it num, op_str, and badchars.

- num: max number of bytes per line (simply for formatting)
- op_str: escaped opcode string ("\\\x41")
- badchars: badchars seperated by a comma ("\\\x00,\\\x0a")

Below is the function definition:

```
analysis(num, op_str, badchars)
```

### Pcolors

pcolors is responsible for processing colors, the only functions that you really need to worry about is `ansi_ljust` it will format colored strings to properly fit the console, usage is simple:

```
ansi_ljust(s, width, rbyte=' ', mode='r')
```

By default spaces / padding will be added to the right side of the string, otherwise it will be placed on the left.

## Adding a new format

When adding a new format it should be placed under the `common/formats` directory. The name chosen for the script will be the new name of the format. As an example let's re-implement the C format under the name `heh.py`. 

```python
  1 from Sickle.common.lib.extract import *
  2 
  3 class module():
  4 
  5   def __init__(self, eobject, robject, varname, badchrs):
  6     self.robject = robject # raw byte object
  7     self.eobject = eobject # escaped object
  8     self.varname = varname # variable name
  9     self.badchrs = badchrs # bad characters
 10 
 11   @staticmethod
 12   def info(info_req):
 13     information = {
 14       "name"        : "heh",
 15       "description" : "dude... what am I doing again?",
 16     }
 17 
 18     return information[info_req]
 19 
 20   # general: general header and payload information
 21   def general(self):
 22     print("Payload size: {:d} bytes".format(self.robject[2]))
 23     print("unsigned char {:s}[] = ".format(self.varname))
 24 
 25   # pformat: simply print the payload to the console
 26   def pformat(self):
 27     results = analysis(60, self.eobject[1], self.badchrs)
 28     self.general()
 29     for i in range(len(results)):
 30       if i == (len(results) -1):
 31         print("\"{:s}\";".format(results[i]))
 32       else:
 33         print("\"{:s}\"".format(results[i]))
```
Let's break down exactly how this works.

- Line 1 we import the extract functions, this will allow us to call the analysis function highlighting any bad characters within our shellcode. Along with this feature it will evenly split bytecode.
- Line 3 we declare this to be a module class
- Lines 5-9 we initialize variables used throughout the formatting
    - robject: raw byte object, contains 3 values you can index within a list
        - robject[0]: filename
        - robject[1]: raw bytes extracted from file
        - robject[2]: total number of bytes within file
    - eobject: escaped byte object contains 3 values you can index within a list
        - eobject[0]: filename
        - eobject[1]: excaped bytes, e.g \\\\x41\\\\x41. These are not raw bytes, rather escaped bytes as a string
        - eobject[2]: total number of bytes with file
- Lines 11-18 we define the name of the format (should keep as the name of the .py script), and a description of the format. 
- Lines 21-23 we simply define a header. This will be called before formatting the payload, completely optional! 
- Lines 26-33 we declare the pformat function. This function will be responsible for formatting the shellcode and will initially be called by the main program.
    - Line 27 we make a call to the analysis function passing the following args
        - num: number of characters to split by in this case 60 meaning the analyzed line will be 15 bytes.
        - op_str: escaped opcode string (do not use robject when using this function)
        - badchars: bad characters to exclude from our payload
        
Perfect! Let's test it

```
# sickle.py -i
Options for format

Formats:

  Name                Description
  ----                -----------
  powershell          Format bytecode for Powershell
  uint8array          Format bytecode for Javascript as a Uint8Array directly
  python              Format bytecode for Python
  raw                 Format bytecode in RAW
  bash                Format bytecode for bash script (UNIX)
  cs                  Format bytecode for C#
  heh                 dude... what am I doing again? <------------ w00tw00t
  ruby                Format bytecode for Ruby
  nasm                Format bytecode for NASM
  escaped             Format bytecode for one-liner hex escape paste
  hex_space           Format bytecode in hex, seperated by a space
  hex                 Format bytecode in hex
  perl                Format bytecode for Perl
  javascript          Format bytecode for Javascript (Blob to send via XHR)
  python3             Format bytecode for Python3
  dword               Format bytecode in dword
  c                   Format bytecode for a C
  java                Format bytecode for Java
  num                 Format bytecode in num format

Description:

  Format bytecode into desired format / language
```

Great and just like that you've added your own format!

## Adding a new dev module

When adding a new development module it should be placed under the `modules/dev` directory. The name chosen for the script will be the new name of the development module. When developing a new module just ask yourself the following questions.

- Does this aid in developing a payload (does not necessarily have to be shellcode and/or bytecode)?
- Does this aid in crafting shellcode and/or debugging shellcode?

If the answer to any of those questions is yes, go for it! Without going into to much detail below is an example of a module (specifically find).

```python
from Sickle.modules.dev.deps import *

class module():

  def __init__(self, arg_list, dynamic_args):
    self.robject = arg_list[0]
    self.arch    = arg_list[2]
    self.varname = arg_list[3]
    self.badchrs = arg_list[4]
    self.modes   = arch_modes() # architectures

  @staticmethod
  def info(info_req):
    information = {
      "name"        : "find",
      "description" : "Find where in shellcode bad characters occur",
    }

    return information[info_req]

  def commented(self):
    opcode_string     = []
    instruction_line  = []
    hex_opcode_string = []

    mode = self.modes[self.arch]

    # seperate the instructions and opcode
    for i in mode.disasm(self.robject[1], 0x1000):
      opcode_string += "{:s}".format(binascii.hexlify(i.bytes).decode('utf-8')),
      instruction_line += "{:s} {:s}".format(i.mnemonic, i.op_str),
    # hex-ify the opcode string
    for i in range(len(opcode_string)):
      line = opcode_string[i]
      hex_opcode_string += "\\x" + "\\x".join([line[i:i+2] for i in range(0, len(line), 2)]),

    ID = colors.BOLD and colors.RED and colors.END

    return [instruction_line, hex_opcode_string, ID]

  def do_thing(self):
    instruction_line, hex_opcode_string, ID = self.commented()
    completed_conversion = []
    results = []

    for i in range(len(hex_opcode_string)):
      results += analysis(66, hex_opcode_string[i], self.badchrs)

    # calculate the longest line
    ll = len(hex_opcode_string[0])
    for i in range(len(hex_opcode_string)):
      if len(hex_opcode_string[i]) > ll:
        ll = len(hex_opcode_string[i])

    for i in range(len(instruction_line)):
      if ID in results[i]:
        h = ansi_ljust(f"{hex_opcode_string[i]}", (ll+1))
        i = f"{colors.BOLD}{colors.RED}# /* {instruction_line[i]} */{colors.END}"
        completed_conversion += f"{h}{i}",
      else:
        h = ansi_ljust(f"{results[i]}", (ll+1))
        i = f"# /* {instruction_line[i]} */"
        completed_conversion += f"{h}{i}",

    for i in range(len(completed_conversion)):
      print(completed_conversion[i])

```

Aside from the general "info function" take note of the "do_thing" function. As you can guess this will be the entry point of your module. You can still define and call other custom functions (e.g commented) however all execution flow should be directed by do_thing. With that said I can't wait to see what you contribute!

