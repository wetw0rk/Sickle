from Sickle.common.lib.extract import *

class module():

  def __init__(self, eobject, robject, varname, badchrs):
    self.robject = robject
    self.eobject = eobject
    self.varname = varname
    self.badchrs = badchrs

  @staticmethod
  def info(info_req):
    information = {
      "name"        : "num",
      "description" : "format bytecode in num format",
    }

    return information[info_req]

  def general(self):
    print("Payload size: {:d} bytes".format(self.robject[2]))

  def pformat(self):
    op_str = ""
    try:
      split_badchar = self.badchars.split(',')
      for i in range(len(split_badchar)):
        mod_badchars += "0x%s," % (split_badchar[i][2:])
      self.badchars = mod_badchars.rstrip(',')
    except:
      pass

    for byte in bytearray(self.robject[1]):
      op_str += "0x{:02x}, ".format(byte)

    self.general()
    results = analysis(84, op_str, self.badchrs)
    for i in range(len(results)):
      snip = len(results[i]) - 2
      if i == (len(results)-1):
        print(results[i][:snip])
      else:
        print(results[i])
