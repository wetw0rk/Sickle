'''

deps.py: This file contains dependencies that may not be installed on systems (e.g capstone).

'''

try:
  from capstone import *
except:
  # if capstone is installed under python2.7 path, import directly
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
