from Sickle.common.lib.extract import *

class module():

  def __init__(self, eobject, robject, varname, badchrs):
    self.robject = robject # raw byte object
    self.eobject = eobject # escaped object
    self.varname = varname # variable name
    self.badchrs = badchrs # bad characters

  @staticmethod
  def info(info_req):
    information = {
      "name"        : "c",
      "description" : "format bytecode for a C (aka the best language in history)",
    }

    return information[info_req]

  # general: general header and payload information
  def general(self):
    print("Payload size: {:d} bytes".format(self.robject[2]))
    print("unsigned char {:s}[] = ".format(self.varname))

  # pformat: simply print the payload to the console
  def pformat(self):
    results = analysis(60, self.eobject[1], self.badchrs)
    self.general()
    for i in range(len(results)):
      if i == (len(results) -1):
        print("\"{:s}\";".format(results[i]))
      else:
        print("\"{:s}\"".format(results[i]))
