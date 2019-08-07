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
      "name"        : "java",
      "description" : "format bytecode for Java",
    }

    return information[info_req]

  def general(self):
    print("Payload size: {:d} bytes".format(self.robject[2]))
    print("byte {:s}[] = new byte[]".format(self.varname))
    print("{")

  def pformat(self):
    op_str = ""
    try:
      split_badchar = self.badchars.split(',')
      for i in range(len(split_badchar)):
        mod_badchars += "(byte) 0x%s," % (split_badchar[i][2:])
      self.badchars = mod_badchars.rstrip(',')
    except:
      pass

    for byte in bytearray(self.robject[1]):
      op_str += " (byte) 0x{:02x},".format(byte)

    results = analysis(104, op_str, self.badchrs)
    self.general()
    for i in range(len(results)):
      print("  " + results[i].lstrip(" "))
    print("};")
