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
      "name"        : "ruby",
      "description" : "Format bytecode for Ruby",
    }
    return information[info_req]

  def general(self):
    print("Payload size: {:d} bytes".format(self.robject[2]))
    print('%s = ""' % self.varname)

  def pformat(self):
    results = analysis(56, self.eobject[1], self.badchrs)
    self.general()
    for i in range(len(results)):
      if i == (len(results) -1):
        print("\"{:s}\"".format(results[i]))
      else:
        print("\"{:s}\" +".format(results[i]))
