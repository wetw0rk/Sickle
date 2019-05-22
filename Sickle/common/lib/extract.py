'''

extract.py: all extraction done on files or bytecode should be done here.

'''

import os
import sys
import codecs
import binascii
import subprocess

from .pcolors import *

# analysis: parse the opcode string in search of bad characters and return the shitty bytes in RED
def analysis(num, op_str, badchars):
  op_line = []
  spotted = []
  results = []

  if badchars != None:
    # split badchars if any
    sep_chars = badchars.split(",")
    for i in range(len(sep_chars)):
      if sep_chars[i] in op_str:
        spotted += ("{:s}".format(sep_chars[i])),

  # here we begin to spot the badchars should we find one
  # we will replace it with a bold and red opcode, simply
  # making identification an ease
  indiv_byte = len(spotted)-1         # loop counter for bad characters

  # the tactical dumping begins here, aiding in spotting badchars
  splits = [op_str[x:x+num] for x in range(0,len(op_str),num)]
  for i in range(len(splits)):
    while indiv_byte > -1:
      if spotted[indiv_byte] in splits[i]:
        highlight_byte = "{:s}{:s}{:s}{:s}".format(colors.BOLD, colors.RED, spotted[indiv_byte], colors.END)
        splits[i] = splits[i].replace(spotted[indiv_byte], highlight_byte)
      indiv_byte -= 1
    indiv_byte = len(spotted)-1

  for i in range(len(splits)):
    results += splits[i],

  return results

# standard_bin: returns 3 objects -> filename, fullcode, and full size. There are 2 modes,
# mode 1 is escape sequences (e.g \\x41\\x42), mode 2 is raw bytes
def standard_bin(dump_src, raw):
  if raw == True:
    fc = ""
    try:
      with open(dump_src, 'rb') as fd:
        fcr = fd.read()
        for byte in bytearray(fcr):
          fc += "\\x{:02x}".format(byte)
      fn = dump_src
      fs = os.path.getsize(dump_src)
    except:
      fcr = dump_src
      for byte in bytearray(fcr):
        fc += "\\x{:02x}".format(byte)
      fn = "STDIN"
      fs = len(fcr)
  else:
    try:
      with open(dump_src, "rb") as fd:
        fc = fd.read()
      fn = dump_src
      fs = os.path.getsize(dump_src)
    except:
      fc = dump_src
      fn = "STDIN"
      fs = len(fc)

  data = [fn, fc, fs]

  return data

# objdump2shellcode: extract opcodes from a binary via objdump. I don't reccomend this
# when developing shellcode try to use a raw.bin
def objdump2shellcode(dumpfile):
  no_junk = []
  no_addr = []
  opcodes = []
  instrut = []
  ops     = ""

  # run objdump to disassemble the binary
  try:
    intel_dump = subprocess.Popen(['objdump', '-D', dumpfile, '-M', 'intel', '--insn-width=15'],
      stdout=subprocess.PIPE).communicate()[0]
  except Exception as e:
    print("Error running objdump command: %s" % e)
    sys.exit()

  # here we begin to clean the output accordingly; this was
  # once a function however after consideration, ideally we
  # we want to reuse the dumping class for stdin, etc
  newline_split = intel_dump.decode().split("\n")

  for i in range(len(newline_split)):
    # split up every line by a [tab] and remove address
    addr_splt = newline_split[i].split('\t')[1:3]
    # get rid of blank lines
    if len(addr_splt) > 0:
      no_addr += addr_splt
    else:
      pass

  # separate opcodes and instructions
  list_len = len(no_addr)
  for i in range(list_len):
    if (i & 1) == 1:
      instrut += no_addr[i],
    else:
      opcodes += no_addr[i],

  # cut off the junk and format (\xde\xad\xbe\xef)
  for i in range(len(opcodes)):
    no_junk  += opcodes[i].rstrip(" "),
  for i in range(len(opcodes)):
    opcodes[i] = opcodes[i].rstrip(" ")
  for i in range(len(opcodes)):
    ops += "\\x%s" % opcodes[i].replace(" ", "\\x")

  str_obj = bytes(ops, 'ascii')
  raw_ops = codecs.escape_decode(str_obj)[0]

  return raw_ops
