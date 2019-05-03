from common.lib.extract import *

class module():

  def __init__(self, eobject, robject, varname, badchrs):
    self.robject = robject
    self.eobject = eobject
    self.varname = varname
    self.badchrs = badchrs

  @staticmethod
  def info(info_req):
    information = {
      "name"        : "javascript",
      "description" : "format bytecode for Javascript (neatly then into a Uint8Array)",
    }

    return information[info_req]

  def general(self):
    print("Payload size: {:d} bytes".format(self.robject[2]))
    print('var %s = "";' % self.varname)
    print('var bytes = [];\n')

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

    results = analysis(60, op_str, self.badchrs)

    self.general()
    for i in range(len(results)):
      print('%s += \"%s\";' % (self.varname, results[i]))

    print("")
    print("/* fp: contains the final payload in proper format */")
    print("for (var i = 0, len = %s.length; i < len; i+=2)" % (self.varname))
    print("{")
    print("  bytes.push(parseInt(%s.substr(i,2),16));" % self.varname)
    print("}")
    print("var fp = new Uint8Array(bytes);")
