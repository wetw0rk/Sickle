from sickle.common.lib.generic import modparser

class ModuleHandler():
    """This class is responsible for calling the appropriate development
    module. All modules should pass through this class

    :param module: Development module to be called
    :type module: str

    :param arg_object: Dictionary object containing arguments that may be required by the
        module
    :type arg_object: dict
    """

    def __init__(self, module, arg_object):

        self.module = module
        self.arg_object = arg_object

    def execute_module(self):
        """Executes development module
        """

        dev_module = modparser.check_module_support("modules", self.module)
        if (dev_module == None):
            return -1

        module = dev_module.Module(self.arg_object)
        module.do_thing()

        return 0

    def print_modules():
        """Prints all currently supported modules along with a short description
        """

        # Get the list objects of data we'll be parsing
        modules = modparser.get_module_list("modules")
        descriptions = [modparser.check_module_support("modules", mod).Module.summary
                        for mod in modules]

        # Get the sizes needed to calculate output strings
        max_mod_len = len(max(modules, key=len))
        if max_mod_len < 0x0D:
            max_mod_len = 0x0D

        max_info_len = len(max(descriptions, key=len))

        # Output the results
        print(f"\n  {'Modules':<{max_mod_len}} {'Description'}")
        print(f"  {'-------':<{max_mod_len}} {'-----------'}")

        for mod, info in zip(modules, descriptions):
            space_used = max_mod_len + 4
            out_list = modparser.get_truncated_list(f"{info}", space_used)
            for i in range(len(out_list)):
                if i != 0:
                    print(f"  {' ' * max_mod_len} {out_list[i]}")
                else:
                    print(f"  {mod:<{max_mod_len}} {out_list[i]}")

        return
