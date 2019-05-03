'''

handler: consider this the body, execution flow is generally directed here

'''

import os
import sys

from modules.dev import *
from modules.formats import *
from common.lib.extract import *

class handle():
  def __init__(self, args):
    self.binfile  = args.read       # read from binary file
    self.format   = args.format     # format
    self.arch     = args.arch       # architecture
    self.stdin    = args.stdin      # read from STDIN
    self.examine  = args.examine    # seperate file being compared
    self.objdump  = args.objdump    # read from ELF / PE
    self.module   = args.module     # module to use on binfile
    self.badchars = args.badchars   # badchars ("\x00,\x41")
    self.varname  = args.varname    # variable name
    self.list     = args.list       # list all formats / archs

    # variables not passed but generated for other functions
    self.formats = self.gather_modules("modules/formats")
    self.modules = self.gather_modules("modules/dev")

  # gather_modules: obtain all modules in modules directory
  def gather_modules(self, directory):
    _modules = os.listdir(directory)
    mod_list = []
    for i in range(len(_modules)):
      if "__" in _modules[i] or ".pyc" in _modules[i]:
        pass
      else:
        mod_list += _modules[i][:-3],
    return mod_list

  # print_modules: pretty self explanitory, print all avialible modules
  def print_modules(self):
    print("{:10} \t {:80}\n".format("MODULE", "DESCRIPTION"))
    for i in range(len(self.modules)):
      try:
        module_deps = eval(self.modules[i])
        print("{:10} \t {:80}".format(
          module_deps.module.info("name"),
          module_deps.module.info("description"),
          )
        )
      except AttributeError:
        continue

    print("\n{:10} \t {:80}\n".format("FORMAT", "DESCRIPTION"))
    for i in range(len(self.formats)):
      module_deps = eval(self.formats[i])
      print("{:10} \t {:80}".format(
        module_deps.module.info("name"),
        module_deps.module.info("description"),
        )
      )
    print("\nARCHITECTURES\n")
    arch = deps.arch_modes()
    for k, v in arch.items():
      print(k)
    exit(0)

  # verify module or format is supported 
  def check_args(self):
    if self.format not in self.formats:
      sys.exit("Currently %s format is not supported" % (self.format))
    if self.module not in self.modules and self.module != None:
      sys.exit("Currently %s module is not supported" % (self.module))

  def handle_args(self):
    if self.list == True:
      self.print_modules()
    else:
      self.check_args()

    if self.stdin == False and self.binfile or self.objdump or self.examine:
      if self.objdump:
        file2check = self.objdump
      elif self.examine:
        if os.path.isfile(self.binfile) is False:
          e = standard_bin(self.binfile, False)
          sys.exit("Error dumping bytecode. Is file present?")
        file2check = self.examine
      else:
        file2check = self.binfile

      if os.path.isfile(file2check) is False:
        sys.exit("Error dumping bytecode. Is file present?")

    if self.stdin == True:
      self.binfile = sys.stdin.buffer.raw.read()

    if self.objdump:
      self.binfile = objdump2shellcode(self.objdump) 

    if self.examine:
      e = standard_bin(self.examine, False)
    else:
      e = "NULL"

    if self.binfile:
      r = standard_bin(self.binfile, False)
      f = standard_bin(self.binfile, True)
      if self.module:
        module = eval(self.module).module([f, r, self.arch, self.varname, self.badchars, e])
        module.do_thing()
        exit(0)
      if self.format:
        payload = eval(self.format).module(f, r, self.varname, self.badchars)
        payload.pformat()
    else:
      print("usage: sickle.py [-h] [-r READ] [-f FORMAT] [-s] [-e EXAMINE] [-obj OBJDUMP]")
      print("                 [-m MODULE] [-a ARCH] [-b BADCHARS] [-v VARNAME] [-l]")
      exit(-1)

