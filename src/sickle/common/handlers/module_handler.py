import os

from sickle.common.lib.generic.mparser import get_module_list
from sickle.common.lib.generic.mparser import check_module_support

class ModuleHandler():
    """This class is responsible for calling the appropriate development module. All modules
    should pass through this class

    :param module: Development module to be called
    :type module: str

    :param arg_object: Dictionary object containing arguments that may be required by the module
    :type arg_object: dict
    """

    def __init__(self, module, arg_object):

        self.module = module
        self.arg_object = arg_object

    def execute_module(self):
        """Executes development module
        """

        # Check and ensure that the module is supported by sickle
        dev_module = check_module_support("modules", self.module)
        if (dev_module == None):
            return -1

        module = dev_module.Module(self.arg_object)
        module.do_thing()

        return 0

    def print_modules():
        """Prints all currently supported modules along with a short description
        """

        modules = get_module_list("modules")
        print(f"\n  {'Modules':<20}{'Description'}")
        print(f"  {'-------':<20}{'-----------'}") 
        for i in range(len(modules)):
            dev_module = check_module_support("modules", modules[i])
            print(f"  {modules[i]:<20}{dev_module.Module.summary}")

        return
