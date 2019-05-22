'''

pcolors.py: colors for dumping. If you use windows and use custom modules your gonna wanna modify this file.

'''

import os

class colors():
  def __init__(self):
    pass

  if os.name == 'posix':
    RED   = '\033[31m'
    BLUE  = '\033[94m'
    BOLD  = '\033[1m'
    GRN   = '\033[92m'
    END   = '\033[0m'
  else:
    RED   = ''
    BLUE  = ''
    BOLD  = ''
    GRN   = ''
    END   = ''
