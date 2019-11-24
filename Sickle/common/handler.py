'''

handler.py: consider this the body, execution flow is generally directed here

'''

import os
import sys

from Sickle.modules.dev import *
from Sickle.common.formats import *
from Sickle.common.lib.extract import *

class handle():

  def __init__(self, args):

    self.binfile  = args.read       # read from binary file
    self.arch     = args.arch       # architecture
    self.pargs    = args.pargs      # X=Y (e.g: LPORT=1337)
    self.module   = args.module     # module to use on binfile
    self.format   = args.format     # format
    self.badchars = args.badchars   # badchars ("\x00,\x41")
    self.varname  = args.varname    # variable name
    self.list     = args.list       # list all formats / archs
    self.info     = args.info       # detailed info for module or payload
    self.help     = args.help       # help message

    # variables not passed but generated for other functions
    root_dir = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..'))
    self.formats = self.gather_modules("%s/common/formats" % root_dir)
    self.modules = self.gather_modules("%s/modules/dev" % root_dir)
    self.archs = self.gather_archs()

  # get_mod_info: obtain module information
  def get_mod_info(self, m):
    print("Options for %s\n" % (m))

    m = eval(m)

    # little bit of a hackish method, but print the format module differently
    try:
      m.module.info("formats")
      print("Formats:\n")
    except:
      print("Options:\n")

    # Try to print the module arguments (if any), else try formats, if not, the module has no args
    try:
      if m.module.info("arguments"):
        print(f"  {'Name':<12}{'Required':<12}{'Description'}")
        print(f"  {'----':<12}{'--------':<12}{'-----------'}")
        for i in range(len(m.module.info("arguments"))):
          print(f"  {m.module.info('arguments')[i]:<12}{m.module.info('arg_reqs')[i]:<12}{m.module.info('arg_descriptions')[i]}")
    except:
      try:
        m.module.info("formats")
        print(f"  {'Name':<20}{'Description'}")
        print(f"  {'----':<20}{'-----------'}")
        for i in range(len(self.formats)):
          format_module = eval(self.formats[i])
          print(f"  {self.formats[i]:<20}{format_module.module.info('description')}")
      except:
        print("  None")
    print("")

    print("Description:\n")
    print(f"  {m.module.info('description')}\n")

    exit(0)

  # gather_modules: obtain all modules in modules directory
  def gather_modules(self, directory):
    _modules = os.listdir(directory)
    mod_list = []
    for i in range(len(_modules)):
      if "deps.py" in _modules[i] or ".pyc" in _modules[i] or "__" in _modules[i]:
        pass
      else:
        mod_list += _modules[i][:-3],

    return mod_list

  # gather_archs: gather all current supported architectures
  def gather_archs(self):
    archs = []
    arch = deps.arch_modes()
    for k, v in arch.items():
      archs += k,
    return archs

  # print_modules: pretty self explanitory, print all avialible modules
  def print_modules(self):

    module = []
    archs = []
   
    print(f"\n  {'Name':<20}{'Description'}")
    print(f"  {'----':<20}{'-----------'}") 
    for i in range(len(self.modules)):
      hook = eval(self.modules[i])
      module += f"  {hook.module.info('name'):<20}{hook.module.info('description')}",
    for i in range(len(module)):
      print(module[i])
    exit(0)

  # verify module or format is supported
  def check_args(self):

    if self.format not in self.formats:
      sys.exit("Currently %s format is not supported" % (self.format))
    if self.module not in self.modules and self.module != None:
      sys.exit("Currently %s module is not supported" % (self.module))
    if self.arch not in self.archs:
      sys.exit("Currently %s architecture is not supported" % (self.arch))

  def usage(self):

    message = (
    "usage: sickle.py [-h] [-r READ] [-f FORMAT] [-m MODULE] [-a ARCH]\n"
    "               [-b BADCHARS] [-v VARNAME] [-i] [-l]\n"
    "\n"
    "Sickle - Payload development tool\n"
    "\n"
    "Optional arguments:\n\n"
    "  -h, --help                        Show this help message and exit\n"
    "  -r READ, --read READ              Read bytes from binary file (use - for\n"
    "                                    stdin)\n"
    "  -f FORMAT, --format FORMAT        Output format (--list for more info)\n"
    "  -m MODULE, --module MODULE        Development module\n"
    "  -a ARCH, --arch ARCH              Select architecture for disassembly\n"
    "  -b BADCHARS, --badchars BADCHARS  Bad characters to avoid in shellcode\n"
    "  -v VARNAME, --varname VARNAME     Alternative variable name\n"
    "  -i, --info                        Print detailed info for module or payload\n"
    "  -l, --list                        List available modules\n\n"
    "Examples:\n\n"
    "  sickle -r old_shellcode.bin -m diff BINFILE=new_shellcode.bin MODE=asm\n"
    "  sickle -r raw.bin -f python3"
    )
    print(message)
    sys.exit(0)

  def handle_args(self):

    self.check_args()

    if self.help == True:
      self.usage()

    if self.list == True:
      self.print_modules()
    elif self.info == True:
      self.get_mod_info(self.module)

    if self.binfile:
      if self.binfile == '-':
        self.binfile = sys.stdin.buffer.raw.read()
      else:
        if os.path.isfile(self.binfile) is False:
          sys.exit("Error dumping bytecode. Is file present?")

    if self.binfile:
      r = standard_bin(self.binfile, False)
      e = standard_bin(self.binfile, True)

    if self.module and self.binfile:
      module = eval(self.module).module(
        [
          r,              # raw byte
          e,              # escaped bytes
          self.arch,      # architecture
          self.varname,   # variable name
          self.badchars,  # badchars
          self.format     # format
        ],
        self.pargs        # Positional args: X=Y (e.g: LPORT=1337)
      )
      module.do_thing()
    else:
      self.usage()
      exit(-1)

