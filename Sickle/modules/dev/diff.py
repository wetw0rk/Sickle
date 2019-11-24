'''

diff: perform comparisons on two binary files in a variety of ways

'''

from Sickle.modules.dev.deps import *

class module():
  
  def __init__(self, static_args, dynamic_args):
    self.robject  = static_args[0] # raw byte object
    self.arch     = static_args[2] # selected architecture
    self.modes    = arch_modes()   # architectures
    self.arg_list = dynamic_args   # X=Y (e.g: LPORT=1337) 

    # variables used throughout the module there may be a better
    # method to avoid truncation, but manual exclusion eliminates
    # dependencies
    self.added   = colors.GREEN
    self.changed = colors.YELLOW
    self.deleted = colors.RED
    self.alike   = colors.END
    self.ccolor  = ""

    self.badbytes = \
    [
      "\x00","\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0a",
      "\x0b","\x0c","\x0d","\x0e","\x0f","\x10","\x11","\x12","\x13","\x14","\x15",
      "\x16","\x17","\x18","\x19","\x1a","\x1b","\x1c","\x1d","\x1e","\x1f","\x7f",
      "\x80","\x81","\x82","\x83","\x84","\x85","\x86","\x87","\x88","\x89","\x8a",
      "\x8b","\x8c","\x8d","\x8e","\x8f","\x90","\x91","\x92","\x93","\x94","\x95",
      "\x96","\x97","\x98","\x99","\x9a","\x9b","\x9c","\x9d","\x9e","\x9f","\xa0"
    ]

  @staticmethod
  def info(info_req):

    information = {
      "name"              : "diff",
      "description"       : "Compare two binaries / shellcode(s). Supports hexdump, byte, raw, and asm modes",
      "arguments"         : ["BINFILE", "MODE"],
      "arg_descriptions"  : ["Additional binary file needed to perform diff", "hexdump, byte, raw, or asm"],
      "arg_reqs"          : ["yes", "yes"],
      "modes"             : ["hexdump", "byte", "raw", "asm"]
    }

    return information[info_req]

  def do_thing(self):

    # if successful returns dictionary {"BINFILE": "", "MODE": ""}
    r = argument_check(module.info("arguments"), self.arg_list)
    if r == -1:
      sys.exit(-1)

    # since this module has specific modes, verify mode is supported
    if r["MODE"] not in module.info("modes"):
      print(f'MODE: {r["MODE"]} not supported by module')
      sys.exit(-1)

    self.legend()

    if os.path.isfile(r["BINFILE"]) is False:
      sys.exit("Error dumping BINFILE. Is file present?")

    fileobj = standard_bin(r["BINFILE"], False)

    if r["MODE"] in ["hexdump", "byte", "raw"]:
      ilist = self.cformat(fileobj)
      if r["MODE"] == "hexdump":
        self.hexdump(ilist)
      elif r["MODE"] == "byte":
        self.bytedump(ilist)
      else:
        self.raw_repr(ilist)
      sys.exit(0)

    self.asm_diff(fileobj)

  # asm_diff: disassemble 2 binary files in the respective architecture
  def asm_diff(self, fileobj):

    original = self.robject
    modified = fileobj

    alpha = self.check_alpha(original[1])
    alpha2 = self.check_alpha(modified[1])

    print(colors.BOLD, colors.GREEN)
    tables = f"{ansi_ljust('FILE1', 26, ' ', 'l')}{ansi_ljust('FILE2', 54, ' ', 'l')}"
    print(tables)
    print(colors.BLUE)
    
    print("Architecture\tAlphanumeric\tSize (bytes)\tSource\tArchitecture\tAlphanumeric\tSize (bytes)\tSource{:s}".format(colors.END).expandtabs(15))
    print("{:s}\t{}\t{:d}\t{:s}\t{:s}\t{}\t{:d}\t{:s}".format(
      self.arch, alpha, original[2], original[0],
      self.arch, alpha2, modified[2], modified[0]
      ).expandtabs(15))
    
    print(colors.BOLD, colors.GREEN)
    tables = f"{ansi_ljust('Disassembly', 29, ' ', 'l')}{ansi_ljust('Disassembly', 54, ' ', 'l')}"
    print(tables)

    print(colors.BLUE)
    tables = f"{ansi_ljust('Address', 10)}{ansi_ljust('Opcode', 21)}{ansi_ljust('Assembly', 31)}{ansi_ljust('Opcode', 25)}{'Assembly'}{colors.END}"
    print(tables)

    og_addr, og_op, og_ins = self.disassemble_bytes(original[0], original[1], original[2])
    md_addr, md_op, md_ins = self.disassemble_bytes(modified[0], modified[1], modified[2])

    final_ops = [
      [], # FILE1
      []  # FILE2
    ]

    final_ins = [
      [], # FILE1
      []  # FILE2
    ]

    if len(og_addr) > len(md_addr):
      loopc = len(og_addr)
    else:
      loopc = len(md_addr)

    index = 0
    for i in range(loopc):
      # opcodes
      try:
        if og_op[i] == md_op[i]:
          final_ops[0] += f"{self.alike}{og_op[i]}{colors.END}",
          final_ops[1] += f"{self.alike}{md_op[i]}{colors.END}",
        else:
          final_ops[0] += f"{self.changed}{og_op[i]}{colors.END}",
          final_ops[1] += f"{self.changed}{md_op[i]}{colors.END}",
      except IndexError:
        if len(md_addr) > len(og_addr):
          final_ops[1] += f"{self.added}{md_op[i]}{colors.END}",
        else:
          final_ops[0] += f"{self.deleted}{og_op[i]}{colors.END}",
      # instructions
      try:
        if og_ins[i] == md_ins[i]:
          final_ins[0] += f"{self.alike}{og_ins[i]}{colors.END}",
          final_ins[1] += f"{self.alike}{md_ins[i]}{colors.END}",
        else:
          final_ins[0] += f"{self.changed}{og_ins[i]}{colors.END}",
          final_ins[1] += f"{self.changed}{md_ins[i]}{colors.END}",
      except IndexError:
        if len(md_addr) > len(og_addr):
          final_ins[1] += f"{self.added}{md_ins[i]}{colors.END}",
        else:
          final_ins[0] += f"{self.deleted}{og_ins[i]}{colors.END}",

    if len(md_addr) > len(og_addr):
      addr_list = md_addr
    else:
      addr_list = og_addr

    for i in range(loopc):
      try:
        og_op = ansi_ljust(f"{final_ops[0][i]}", 21)
        og_in = ansi_ljust(f"{final_ins[0][i]}", 31)
        md_op = ansi_ljust(f"{final_ops[1][i]}", 25)
        md_in = ansi_ljust(f"{final_ins[1][i]}", 25)
        print(f"{addr_list[i]:<10}{og_op}{og_in}{md_op}{md_in}")
      except IndexError:
        if len(md_addr) > len(og_addr):
          t_op = ansi_ljust(f"{final_ops[1][i]}", 25)
          t_in = ansi_ljust(f"{final_ins[1][i]}", 25)
          print(f"{addr_list[i]:<62}{t_op}{t_in}")
        else:
          t_op = ansi_ljust(f"{final_ops[0][i]}", 21)
          t_in = ansi_ljust(f"{final_ins[0][i]}", 31)
          print(f"{addr_list[i]:<10}{t_op}{t_in}")

  # disassemble_bytes: core of the disassembly using capstone
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

  # check_alpha: check if the buffer is completely alphanumeric
  def check_alpha(self, shellcode):

    alpha = None
    try:
      shellcode.decode('ascii')
    except:
      alpha = False

    return alpha

  # raw_repr: print both binary files as strings escaping
  # non-printable characters
  def raw_repr(self, results):

    strs = ["", ""]

    # similiar approach as the prevous diffs, only this
    # time we needn't worry about indexing
    for i in range(len(results)):
      for j in range(len(results[i])):
        c = results[i][j]

        if self.added in c:
          self.ccolor = self.added
        elif self.changed in c:
          self.ccolor = self.changed
        elif self.deleted in c:
          self.ccolor = self.deleted
        else:
          self.ccolor = self.alike

        c = int(c.lstrip(self.ccolor).lstrip(' '))
        c = repr(chr(c))[1:-1]
        strs[i] += f"{self.ccolor}{c}{colors.END}"

    print(f"{colors.BOLD}{colors.BLUE}{'FILE1'}{colors.END}: {strs[0]}\n")
    print(f"{colors.BOLD}{colors.BLUE}{'FILE1'}{colors.END}: {strs[1]}\n")

  # bytedump: dump both binfiles side by side, viewing opcodes and raw
  # format
  def bytedump(self, results):
    
    print(f"{colors.BOLD}{colors.BLUE}{'FILE1':>31}{'FILE2':>30}\n")
    print(f"{colors.BOLD}{colors.BLUE}{'BYTES':>26} {'RAW':>8}{'BYTES':>21} {'RAW':>8}{colors.END}\n")

    if len(results[0]) > len(results[1]):
      loopc = len(results[0])
    else:
      loopc = len(results[1])

    hex_byte = [
      "", # FILE1
      ""  # FILE2
    ]
    asc_byte = [
      "", # FILE1
      ""  # FILE2
    ]

    # similiar operation to hexdump mode
    index = 0
    for i in range(loopc):
      try:
        if results[0][i] != results[1][i]:
          self.ccolor = self.changed
        else:
          self.ccolor = self.alike

        r0 = int(results[0][i].lstrip(self.ccolor).lstrip(' '))
        r1 = int(results[1][i].lstrip(self.ccolor).lstrip(' '))
  
        hex_byte[0] = ansi_ljust(f"{self.ccolor}{hex(r0)[2:]:0>2}{colors.END}", 23, ' ', 'l')
        hex_byte[1] = ansi_ljust(f"{self.ccolor}{hex(r1)[2:]:0>2}{colors.END}", 17, ' ', 'l')

        asc_byte[0] = ansi_ljust(f"{self.ccolor}{repr(chr(r0))}{colors.END}", 11, ' ', 'l')
        asc_byte[1] = ansi_ljust(f"{self.ccolor}{repr(chr(r1))}{colors.END}", 11, ' ', 'l')

        print(f"{hex_byte[0]} {asc_byte[0]} {hex_byte[1]} {asc_byte[1]}")
        index += 1
      except IndexError:
        if len(results[1]) > len(results[0]):
          self.ccolor = self.added
          while index != loopc:
            r1 = int(results[1][index].lstrip(self.ccolor).lstrip(' '))
            hex_byte[1] = ansi_ljust(f"{self.ccolor}{hex(r1)[2:]:0>2}{colors.END}", 53, ' ', 'l')
            asc_byte[1] = ansi_ljust(f"{self.ccolor}{repr(chr(r1))}{colors.END}", 11, ' ', 'l')

            print(f"{hex_byte[1]} {asc_byte[1]}")
            index += 1
        else:
          self.ccolor = self.deleted
          while index != loopc:
            r0 = int(results[0][index].lstrip(self.ccolor).lstrip(' '))
            hex_byte[0] = ansi_ljust(f"{self.ccolor}{hex(r0)[2:]:0>2}{colors.END}", 23, ' ', 'l')
            asc_byte[0] = ansi_ljust(f"{self.ccolor}{repr(chr(r0))}{colors.END}", 11, ' ', 'l')

            print(f"{hex_byte[0]} {asc_byte[0]}")
            index += 1

  # hexdump: perform a hexdump diff on both binary files provided (-r) and binfile
  def hexdump(self, results):

    print(f"{colors.BOLD}{colors.BLUE}{'FILE1':>53}{'FILE2':>68}{colors.END}\n")

    chunks  = [
      [results[0][i:i + 16] for i in range(0, len(results[0]), 16)], # FILE1
      [results[1][i:i + 16] for i in range(0, len(results[1]), 16)]  # FILE1
    ]

    hexdump_strs = [
      [], # FILE1
      []  # FILE2
    ]

    ascii_strs = [
      [], # FILE1
      []  # FILE1
    ]

    index = 0
    tmp = ""
    c = 0

    # format opcodes and ASCII strings to later be printed
    for i in range(len(chunks)):
      for j in range(len(chunks[i])):
        for k in range(len(chunks[i][j])):
          clist = chunks[i][j]
          
          if self.added in clist[k]:
            self.ccolor = self.added
          elif self.changed in clist[k]:
            self.ccolor = self.changed
          elif self.deleted in clist[k]:
            self.ccolor = self.deleted
          else:
            self.ccolor = self.alike

          c = int(clist[k].lstrip(self.ccolor).lstrip(' '))
          c = f"{hex(c)[2:]:0>2}"

          tmp += f" {self.ccolor}{c}{colors.END}"

        hexdump_strs[i] += tmp.lstrip(' '),
        tmp = ""
        
        for k in range(len(chunks[i][j])):
          clist = chunks[i][j]

          if self.added in clist[k]:
            self.ccolor = self.added
          elif self.changed in clist[k]:
            self.ccolor = self.changed
          elif self.deleted in clist[k]:
            self.ccolor = self.deleted
          else:
            self.ccolor = self.alike

          c = int(clist[k].lstrip(self.ccolor).lstrip(' '))
          c = chr(c)
          
          if c in self.badbytes:
            c = '.'

          tmp += f"{self.ccolor}{c}{colors.END}"

        ascii_strs[i] += tmp,
        tmp = ""

    # print results, we will leverage the indexerror to detect
    # any additional bytes
    if len(hexdump_strs[0]) > len(hexdump_strs[1]):
      hexdump_loopc = len(hexdump_strs[0])
    else:
      hexdump_loopc = len(hexdump_strs[1])

    ao = ""
    index = 0
    hex_str = ["", ""]
    ascii_str = ["", ""]
    for i in range(hexdump_loopc):
      try:
        ao = hex(i * 16)[2:]

        hex_str[0] = ansi_ljust(hexdump_strs[0][i], 48)
        hex_str[1] = ansi_ljust(hexdump_strs[1][i], 48)

        ascii_str[0] = ansi_ljust(f"|{ascii_strs[0][i]}|", 18)
        ascii_str[1] = ansi_ljust(f"|{ascii_strs[1][i]}|", 18)

        index += 1
        print(f"{ao:0>16} {hex_str[0]} {ascii_str[0]} {hex_str[1]} {ascii_str[1]}")
      except IndexError:
        if len(hexdump_strs[1]) > len(hexdump_strs[0]):
          self.ccolor = self.added
          while index != hexdump_loopc:
            ao = hex(index * 16)[2:]
            ao = f"{ao:0>16}"
            ao = ansi_ljust(ao, 84)

            hex_str[1] = ansi_ljust(hexdump_strs[1][index], 48)

            ascii_str[1] = ansi_ljust(f"|{ascii_strs[1][index]}|", 18)
            print(f"{ao:0>16} {hex_str[1]} {ascii_str[1]}")
            index += 1

        else:
          self.ccolor = self.deleted
          while index != hexdump_loopc:
            ao = hex(index * 16)[2:]
            ao = f"{ao:0>16}"

            hex_str[0] = ansi_ljust(hexdump_strs[0][index], 48)
            ascii_str[0] = ansi_ljust(f"|{ascii_strs[0][index]}|", 18)
              
            print(f"{ao:0>16} {hex_str[0]} {ascii_str[0]}")
            index += 1
    print("")

  # cformat: this function will take the first file (-r) and the second
  # file object to create a nested list containing colored bytes. this
  # function is utilized by hexdump, byte, and raw modes.
  def cformat(self, fileobj):

    results = [
      [], # FILE1
      []  # FILE2
    ]

    print(f"\n  Sizeof FILE1 ({self.robject[0]}): {self.robject[2]}")
    print(f"  Sizeof FILE2 ({fileobj[0]}): {fileobj[2]}\n")

    # loop over the larger file (will acccount for indexing)
    if fileobj[2] > self.robject[2]:
      loopc = fileobj[2]
    else:
      loopc = self.robject[2]

    # format each byte into a color + ascii int
    index = 0
    for i in range(loopc):
      try:
        if self.robject[1][i] != fileobj[1][i]:
          self.ccolor = self.changed
        else:
          self.ccolor = self.alike

        results[0] += f"{self.ccolor} {self.robject[1][i]:0>2}",
        results[1] += f"{self.ccolor} {fileobj[1][i]:0>2}",
        index += 1
      except IndexError:
        if fileobj[2] > self.robject[2]:
          self.ccolor = self.added
          while index != fileobj[2]:
            results[1] += f"{self.ccolor} {fileobj[1][index]:0>2}",
            index += 1
        else:
          self.ccolor = self.deleted
          while index != self.robject[2]:
            results[0] += f"{self.ccolor} {self.robject[1][index]:0>2}",
            index += 1

    return results

  # legend: this will contain the color definitions when performing any
  # diffing.
  def legend(self):
    print(f"\n{colors.BOLD}{colors.BLUE}Legend{colors.END}\n")
    print(f"\t[ {colors.BOLD}Alike{colors.END} ]")
    print(f"\t[{colors.BOLD}{colors.GREEN} Added {colors.END}]")
    print(f"\t[{colors.BOLD}{colors.YELLOW}Changed{colors.END}]")
    print(f"\t[{colors.BOLD}{colors.RED}Deleted{colors.END}]\n")
    return
