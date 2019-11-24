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
      "name"        : "uint8array",
      "description" : "Format bytecode for Javascript as a Uint8Array directly",
      "modes"       : ["payload"]
    }

    return information[info_req]

  def general(self):
    print("Payload size: {:d} bytes".format(self.robject[2]))

  def pformat(self):
    op_str = "var %s = new Uint8Array([" % self.varname

    self.general()
    for byte in bytearray(self.robject[1]):
      op_str += "%d, " % byte
    op_str = "%s]);" % op_str[:-2]
    print(op_str)
