'''

disassemble: disassemble bytes in X arch

'''

from Sickle.modules.dev.deps import *
from Sickle.common.lib.extract import *

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
      "name"        : "disassemble",
      "description" : "disassemble bytecode in respective architecture"
    }

    return information[info_req]

  def check_alpha(self, shellcode):
    alpha = None
    try:
      shellcode.decode('ascii')
    except:
      alpha = False
    return alpha

  def disassemble_bytes(self, source_file, shellcode, sc_size):
    instruction = []
    address     = []
    opcode      = []

    mode = self.modes[self.arch]

    try:
      for i in mode.disasm(shellcode, 0x10000000):
        address     += "%x" % i.address,
        opcode      += binascii.hexlify(i.bytes).decode('utf-8'),
        instruction += "%s %s" % (i.mnemonic, i.op_str),
    except CsError as e:
      print("Something went wrong: {:s}".format(e))

    return address, opcode, instruction

  def do_thing(self):
    rbytes = self.robject
    completed_check = []

    sc_adr, sc_ops, sc_ins = self.disassemble_bytes(rbytes[0], rbytes[1], rbytes[2])

    alpha = self.check_alpha(rbytes[1])

    print("%s%s" % (colors.BOLD, colors.GRN)),
    print("[Bytearray information]".center(60)),
    print(colors.BLUE),
    print("Architecture\tAlphanumeric\tSize (bytes)\tSource{:s}".format(colors.END).expandtabs(15)),
    print("{:s}\t{}\t{:d}\t{:s}".format(self.arch, alpha, rbytes[2], rbytes[0]).expandtabs(15)),
    print("%s%s" % (colors.BOLD, colors.GRN)),
    print("[Shellcode disassembly]".center(60)),
    print(colors.BLUE),
    print("Address\tOpCodes\tAssembly{:s}".format(colors.END).expandtabs(22)),

    for i in range(len(sc_adr)):
      completed_check += ("%s\t%s\t%s" % (
        sc_adr[i],
        sc_ops[i],
        sc_ins[i],
      )).expandtabs(22),

    for i in range(len(completed_check)):
      print(completed_check[i])
