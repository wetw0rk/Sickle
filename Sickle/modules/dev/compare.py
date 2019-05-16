'''

compare: compare two binary files and view differences

'''

from Sickle.modules.dev.deps import *
from Sickle.common.lib.extract import *

class module():
  
  def __init__(self, arg_list):
    self.robject = arg_list[1]
    self.arch    = arg_list[2]
    self.varname = arg_list[3]
    self.badchrs = arg_list[4]
    self.examine = arg_list[5]
    self.modes   = arch_modes() # architectures

  @staticmethod
  def info(info_req):
    information = {
      "name"        : "compare",
      "description" : "compare two binary files and view differences"
    }

    return information[info_req]

  def check_alpha(self, shellcode):
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
    if self.examine == "NULL":
      print("Error dumping bytecode. Is file present?")
      exit(-1)

    original = self.robject
    modified = self.examine

    og_addr, og_op, og_ins = self.disassemble_bytes(original[0], original[1], original[2])
    md_addr, md_op, md_ins = self.disassemble_bytes(modified[0], modified[1], modified[2])

    final_ops = []
    final_asm = []
    final_end = []
    final_ogc = []

    if len(og_addr) > len(md_addr):
      loopc = len(og_addr)
    else:
      loopc = len(md_addr)

    for i in range(loopc):
      # opcode manipulation
      try:
        if og_op[i] == md_op[i]:
          final_ops += ("%s%s%s%s" % (colors.BOLD, colors.BLUE, md_op[i], colors.END)),
        else:
          final_ops += ("%s%s%s%s" % (colors.BOLD, colors.RED, md_op[i], colors.END)),
      except IndexError:
        try:
          final_ops += ("%s%s%s%s" % (colors.BOLD, colors.GRN, md_op[i], colors.END)),
        except:
          pass

      # instruction manipulation
      try:
        if og_ins[i] == md_ins[i]:
          final_asm += ("%s%s%s%s" % (colors.BOLD, colors.BLUE, og_ins[i], colors.END)),
        else:
          final_asm += ("%s%s%s%s" % (colors.BOLD, colors.RED, md_ins[i], colors.END)),
      except IndexError:
        try:
          final_asm += ("%s%s%s%s" % (colors.BOLD, colors.GRN, md_ins[i], colors.END)),
        except:
          pass

    for i in range(len(final_asm)):
      final_end += ("%s\t%s" % (
        final_ops[i],
        final_asm[i],
      )).expandtabs(35),

    for i in range(len(og_addr)):
      final_ogc += ("%s\t%s" % (
        og_op[i],
        og_ins[i],
      )).expandtabs(22),

    alpha   = self.check_alpha(original[1])
    alpha2  = self.check_alpha(modified[1])

    print(colors.BOLD, colors.GRN)
    print("\t[Original information]\t\t[Modified information]".expandtabs(25))
    print(colors.BLUE)
    print("Architecture\tAlphanumeric\tSize (bytes)\tSource\tArchitecture\tAlphanumeric\tSize (bytes)\tSource{:s}".format(colors.END).expandtabs(15))
    print("{:s}\t{}\t{:d}\t{:s}\t{:s}\t{}\t{:d}\t{:s}".format(
      self.arch, alpha, original[2], original[0],
      self.arch, alpha2, modified[2], modified[0]
    ).expandtabs(15))
    print(colors.BOLD, colors.GRN)
    print("\t[Shellcode disassembly]\t\t[Shellcode disassembly]".expandtabs(25))
    print(colors.BLUE)
    print("OpCodes\t  Assembly\t\tOpCodes\t  Assembly{:s}".format(colors.END).expandtabs(20))

    if len(final_ogc) > len(final_end):
      loopc = len(final_ogc)
    else:
      loopc = len(final_end)

    for i in range(loopc):
      try:
        if len(final_ogc[i]) != 60:
          num_spaces = 60 - len(final_ogc[i])
          final_ogc[i] = final_ogc[i] + " " * num_spaces

        print("%s\t%s".expandtabs(0) % (final_ogc[i], final_end[i]))
      except:
        if len(final_ogc) > len(final_end):
          print("%s".expandtabs(0) % (final_ogc[i]))
        else:
          print("\t%s".expandtabs(60) % (final_end[i]))
