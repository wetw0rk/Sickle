'''

format: default module, will format raw bytes aka bin file. (-r)

'''

from Sickle.common.formats import *
from Sickle.modules.dev.deps import *

class module():

  def __init__(self, static_args, dynamic_args):
    self.robject = static_args[0]
    self.eobject = static_args[1]
    self.varname = static_args[3]
    self.badchrs = static_args[4]
    self.format  = static_args[5]

  @staticmethod
  def info(info_req):

    information = {
      "name"        : "format",
      "description" : "Format bytecode into desired format / language (-f)",
      "formats"     : "",
    }

    return information[info_req]

  def do_thing(self):

    payload = eval(self.format).module(
      self.eobject,
      self.robject,
      self.varname,
      self.badchrs
    )
    payload.pformat()
