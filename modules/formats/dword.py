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
      "name"        : "dword",
      "description" : "format bytecode in dword",
    }

    return information[info_req]

  def general(self):
    print("Payload size: {:d} bytes".format(self.robject[2]))

  def pformat(self):
    op_str = ""
    dwrd= ""
    dlst= []

    # setup bad chars properly
    try:
      split_badchar = self.badchrs.split(',')
      for i in range(len(split_badchar)):
        mod_badchars += "%s," % (split_badchar[i][2:])
      self.badchars = mod_badchars.rstrip(',')
    except:
      pass

    for byte in bytearray(self.robject[1]):
      dwrd += "{:02x}".format(byte)

    # format the hex bytes into dword
    splits = [dwrd[x:x+8] for x in range(0,len(dwrd),8)]
    for i in range(len(splits)):
      s = splits[i]
      dlst += "0x" + "".join(map(str.__add__, s[-2::-2] ,s[-1::-2])),
    for i in range(int(len(dlst)/8+1)):
      op_str += ", ".join(dlst[i*8:(i+1)*8])

    # send it of for character character_analysis
    results = analysis(94, op_str, self.badchrs)
    self.general()
    for i in range(len(results)):
      print(results[i])
