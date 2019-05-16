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
      "name"        : "escaped",
      "description" : "format bytecode for one-liner hex escape paste (e.g \x42\x42)",
    }

    return information[info_req]

  def general(self):
    print("Payload size: {:d} bytes".format(self.robject[2]))

  def pformat(self):
    ops = ""
    results = analysis(60, self.eobject[1], self.badchrs)
    for i in range(len(results)):
      ops += results[i]
    self.general()
    print(ops)
