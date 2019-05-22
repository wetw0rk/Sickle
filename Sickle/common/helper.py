'''

helper.py: handles all arguments passed to sickle

'''

import argparse

def parser():

  parser = argparse.ArgumentParser(description="Sickle - Payload development tool")
  parser.add_argument("-r", "--read",help="read bytes from binary file (any file)")
  parser.add_argument("-f", "--format",default='c',type=str,help="output format (--list for more info)")
  parser.add_argument("-s", "--stdin",help="read ops from stdin (EX: echo -ne \"\\xde\\xad\\xbe\\xef\" | sickle -s -f <format> -b '\\x00')", action="store_true")
  parser.add_argument("-e", "--examine",help="examine a separate file containing original shellcode. mainly used to see if shellcode was recreated successfully")
  parser.add_argument("-obj","--objdump",help="binary to use for shellcode extraction (via objdump method)")
  parser.add_argument("-m", "--module", help="development module")
  parser.add_argument("-a", "--arch",default="x86_32",type=str,help="select architecture for disassembly")
  parser.add_argument("-b", "--badchars",help="bad characters to avoid in shellcode")
  parser.add_argument("-v", "--varname",default='buf',type=str,help="alternative variable name")
  parser.add_argument("-l", "--list",help="list all available formats and arguments", action="store_true")

  args = parser.parse_args()

  return args
