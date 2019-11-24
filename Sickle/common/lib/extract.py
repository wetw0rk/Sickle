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
