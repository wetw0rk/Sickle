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
      "name"        : "hex",
      "description" : "Format bytecode in hex",
    }

    return information[info_req]

  def general(self):
    print("Payload size: {:d} bytes".format(self.robject[2]))

  def pformat(self):
    op_str = ""
    ops = ""
    # setup bad chars properly
    try:
      split_badchar = self.badchrs.split(',')
      for i in range(len(split_badchar)):
        mod_badchars += "%s," % (split_badchar[i][2:])
      self.badchrs = mod_badchars.rstrip(',')
    except:
      pass

    for byte in bytearray(self.robject[1]):
      op_str += "{:02x}".format(byte)

    results = analysis(8, op_str, self.badchrs)
    for i in range(len(results)):
      ops += results[i]

    self.general()
    print(ops)
