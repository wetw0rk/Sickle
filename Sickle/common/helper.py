'''

helper.py: handles all arguments passed to sickle

'''

import argparse

def parser():

  formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=52)
  parser = argparse.ArgumentParser(description="Sickle - Payload development framework", formatter_class=formatter, add_help=False)
  parser.add_argument("pargs", nargs="*")
  parser.add_argument('-h', '--help', default=False, action="store_true")
  parser.add_argument("-r", "--read", help="Read bytes from binary file (use - for stdin)")
  parser.add_argument("-f", "--format", default='c', type=str, help="Output format (--list for more info)")
  parser.add_argument("-m", "--module", default="format", help="Development module")
  parser.add_argument("-a", "--arch", default="x86_32", type=str, help="Select architecture for disassembly")
  parser.add_argument("-b", "--badchars", help="Bad characters to avoid in shellcode")
  parser.add_argument("-v", "--varname",  default='buf', type=str, help="Alternative variable name")
  parser.add_argument("-i", "--info", help="Print detailed info for module or payload", action="store_true")
  parser.add_argument("-l", "--list", help="List available formats, payloads, or modules",  action="store_true")

  args = parser.parse_args()

  return args
