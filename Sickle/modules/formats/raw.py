from Sickle.common.lib.extract import *

# Module for Sickle by: Joseph McPeters (liquidsky)

class module():

  def __init__(self, eobject, robject, varname, badchrs):
    self.robject = robject
    self.eobject = eobject
    self.varname = varname
    self.badchrs = badchrs

  @staticmethod
  def info(info_req):
    information = {
      "name"        : "raw",
      "description" : "format bytecode in RAW",
    }

    return information[info_req]

  def general(self):
    rbytes = self.robject
    sys.stderr.write("Payload size: {:d} bytes\n".format(rbytes[2]))
    sys.stdout.buffer.write(rbytes[1])
    

  def pformat(self):
    ops = ""
    results = []
    self.general()
    for i in range(len(results)):
        ops += results[i]
