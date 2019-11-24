'''

pinpoint: find what instruction(s) are causing issues in your shellcode

'''

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
      "name"        : "pinpoint",
      "description" : "Pinpoint where in shellcode bad characters occur",
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
