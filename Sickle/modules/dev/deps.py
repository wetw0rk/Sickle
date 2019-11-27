'''

deps.py: handle common dependencies such as capstone

'''

from Sickle.common.lib.extract import *

try:
  from capstone import *
except:
  # If capstone is installed under python2.7 path, import directly
  # else fails we are on a Windows OS
  try:
    import importlib.machinery
    path_var = "/usr/lib/python2.7/dist-packages/capstone/__init__.py"
    capstone = importlib.machinery.SourceFileLoader(
      'capstone', path_va
    ).load_module()

    from capstone import *
  except:
    pass

def arch_modes():
  try:
    architecture_mode =  {
      'x86_32'    : Cs(CS_ARCH_X86,   CS_MODE_32),
      'x86_64'    : Cs(CS_ARCH_X86,   CS_MODE_64),
      'mips32'    : Cs(CS_ARCH_MIPS,  CS_MODE_32),
      'mips64'    : Cs(CS_ARCH_MIPS,  CS_MODE_64),
      'arm'       : Cs(CS_ARCH_ARM,   CS_MODE_ARM),
      'arm64'     : Cs(CS_ARCH_ARM64, CS_MODE_ARM),
      'arm_thumb' : Cs(CS_ARCH_ARM,   CS_MODE_THUMB)
    }
  except:
    print("Failed to load capstone")
    exit(-1)
  return architecture_mode

# argument_check: Verify that the users arguments will work
# on the current module. If so, return dictionary.
def argument_check(module_arguments, user_arguments):

  adict = {} # returned dictionary
  olist = [] # optional arg list
  elist = [] # expected arg list
  ulist = [] # user list
  fails = ""
  check = 0

  for k, v in module_arguments.items():
    if v[0] == "yes":
      elist += k,
    olist += k,

  try:

    for i in range(len(user_arguments)):

      arg = user_arguments[i].split('=')[0]
      var = user_arguments[i].split('=')[1]

      if arg not in olist:
        continue
      else:
        ulist += arg,
        adict[arg] = var

  except:

    print("Error parsing arguments")
    sys.exit(-1)

  for i in range(len(elist)):
    if elist[i] not in ulist:
      fails += "{:s}, ".format(elist[i])
      check = 1

  if check == 1:
    print(f"Missing arguments: {fails.rstrip(', ')}")
    return -1

  for k,v in adict.items():
    if len(v) < 1:
      print("Empty arguments")
      sys.exit(-1)
  return adict
