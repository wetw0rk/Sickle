# Sickle Documentation

Crafting your own modules for sickle or adding a new format is simple. This design was recently re-implemented to avoid constant updates to the main program.

## Adding a new format

When adding a new format it should be placed under the `modules/formats` directory. The name chosen for the script will be the new name of the format. As an example let's re-implement the C format under the name `heh.py`. 

```python
1 from common.lib.extract import *
2 
3 class module():
4
5   def __init__(self, eobject, robject, varname, badchrs):
6     self.robject = robject # raw byte object
7     self.eobject = eobject # escaped object
8     self.varname = varname # variable name
9     self.badchrs = badchrs # bad characters
10
11  @staticmethod
12  def info(info_req):
13    information = {
14      "name"        : "heh",
15      "description" : "dude... what am I doing again?",
16    }
17
18    return information[info_req]
19
20  # general: general header and payload information
21  def general(self):
22    print("Payload size: {:d} bytes".format(self.robject[2]))
23    print("unsigned char {:s}[] = ".format(self.varname))
24
25  # pformat: simply print the payload to the console
26  def pformat(self):
27    results = analysis(60, self.eobject[1], self.badchrs)
28    self.general()
29    for i in range(len(results)):
30      if i == (len(results) -1):
31        print("\"{:s}\";".format(results[i]))
32      else:
33        print("\"{:s}\"".format(results[i]))
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
- Lines 11-18 we define the name of the format (should keep as the name of the .py script for ease), and a description of the format. 
- Lines 21-23 we simply define a header. This will be called before formatting the payload, completely optional! 
- Lines 26-33 we declare the pformat function. This function will e responsible for formatting the shellcode and will initially be called by the main program.
    - Line 27 we make a call to the analysis function passing the following args
        - num: number of characters to split by in this case 60 meaning the analyzed line will be 15 bytes.
        - op_str: escaped opcode string (do not use robject when using this function)
        - badchars: bad characters to exclude from our payload
        
Perfect! Let's test it

```
# sickle -l
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
heh        	 dude... what am I doing again?                                     <--- W00TW00T                                       
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
```

Great and just like that you've added your own format!

## Adding a new dev module

When adding a new development module it should be placed under the `modules/dev` directory. The name chosen for the script will be the new name of the development module. When developing a new module just ask yourself the following questions.

- Does this aid in developing a payload (does not necessarily have to be shellcode and/or bytecode)?
- Does this aid in crafting shellcode and/or debugging shellcode?

If the answer to any of those questions is yes, go for it! Without going into to much detail below is an example of a module (specifically pinpoint).

```python
from modules.dev.deps import *
from common.lib.extract import *

class module():

  def __init__(self, arg_list):
    self.robject = arg_list[1]
    self.arch    = arg_list[2]
    self.varname = arg_list[3]
    self.badchrs = arg_list[4]
    self.modes   = arch_modes() # architectures

  @staticmethod
  def info(info_req):
    information = {
      "name"        : "pinpoint",
      "description" : "pinpoint where in your shellcode bad characters occur",
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

    for i in range(len(instruction_line)):
      if ID in results[i]:
        completed_conversion += ("\"%s\"\t %s%s// %s%s" % (
          hex_opcode_string[i],
          colors.BOLD,
          colors.RED,
          instruction_line[i],
          colors.END)
        ).expandtabs(40),
      else:
        completed_conversion += ("\"%s\"\t // %s" % (
          results[i],
          instruction_line[i])
        ).expandtabs(40),

    for i in range(len(completed_conversion)):
      print(completed_conversion[i])
```

Aside from the general "info function" take note of the "do_thing" function. As you can guess this will be the entry point of your module. You can still define and call other custom functions (e.g commented) however all execution flow should be directed by do_thing. With that said I can't wait to see what you contribute!

