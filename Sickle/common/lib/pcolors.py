'''

pcolors.py: process colors for dumping. If you use windows and use custom modules your gonna wanna modify this file.

'''

import os

class colors():
  
  def __init__(self):
    pass

  if os.name != 'posix':
    os.system('color')

  RED     = '\033[31m'
  BLUE    = '\033[94m'
  BOLD    = '\033[1m'
  YELLOW  = '\033[93m'
  GREEN   = '\033[32m'
  END     = '\033[0m'

# ansi_ljust: adjust for colors in the string by adding padding, heavily inspired by Jonathan Eunice
# as seen in his stack overflow reply. The main difference is the colors have been made static.
#
# s     : string
# width : needed block size
# rbyte : replacement byte
# mode  : add spaces right or left
#
# https://stackoverflow.com/questions/14140756/python-s-str-format-fill-characters-and-ansi-colors
def ansi_ljust(s, width, rbyte=' ', mode='r'):

  # get the total number of "color" occurences
  cbuff_len = \
  (
    s.count(colors.GREEN)  * len(colors.GREEN)  +
    s.count(colors.RED)    * len(colors.RED)    +
    s.count(colors.YELLOW) * len(colors.YELLOW) +
    s.count(colors.END)    * len(colors.END)
  )

  # calculate the string length if no color
  slen = len(s) - cbuff_len
  needed = width - slen

  # if needed pad the string
  if needed > 0 and slen != width:
    if mode == 'r':
      return s + rbyte * needed
    else:
      return rbyte * needed + s
  else:
    return s
