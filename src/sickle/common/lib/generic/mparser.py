import os
import sys
import importlib

def get_truncated_list(full_string, space_used):
    """Genereate
    """

    max_str_len = os.get_terminal_size(0).columns
    max_str_len -= space_used
   
    lines = []
    current_line = ""

    if (len(full_string) < max_str_len):
        return [full_string]

    words = full_string.split(" ")

    for word in words:
        if len(word) > max_str_len:
            lines += word,
            continue

        if not current_line:
            current_line = word
        elif len(current_line) + 1 + len(word) <= max_str_len:
            current_line += ' ' + word
        else:
            lines.append(current_line)
            current_line = word

    if current_line:
        lines.append(current_line)

    return lines

def get_module_list(target_path):
    """Returns a list of modules in a given path. Should the caller request it,
    the sub directories will also be included in each discovered module.

    :param target_path: The target path to search for modules. Modules in this context
        refers to anything that needs to be dynamically loaded (e.g formats, payloads).
    :type target_path: str

    :return: A list of module names
    :rtype: list
    """

    module_list = []
    modules_path = f"{os.path.dirname(__file__)}/../../../{target_path}"

    # Here we traverse into the target module directory. If we are including the
    # sub directories, we have to remove the target path and traversal path. In
    # order to work under Windows we convert '\\' to '/'
    for root, dirs, files in os.walk(modules_path):
        for file in files:
            if (file.endswith(".py") and ("__" not in file)):
                module_name = f"{file[:-3]}"
                module_name = f"{root}/{module_name}"
                module_name = module_name[module_name.find(target_path):]
                module_name = module_name.lstrip(f"{target_path}")
                module_name = module_name.replace('\\', '/')
                module_list.append(module_name[1:])

    return module_list

def check_module_support(module_class, module_name):
    """Checks if the module is currently supported by sickle, if so this function
    will return the module object imported by python.

    :param module_class: The type of module we will be verifying support for. This
        is different than the module name itself. This is the category of module.
    :type module_class: str

    :param module_name: The name of the module, this would be the module being called
    :type module_name: str

    :return: The module class object
    :rtype: module
    """

    supported_modules = get_module_list(module_class)
    if (module_name not in supported_modules):
        sys.exit(f"Currently {module_name} {module_class[:-1]} is not supported")
        return None

    try:
        imported_module = importlib.import_module(f"sickle.{module_class}.{module_name.replace('/', '.')}")
    except Exception as e:
        sys.exit(f"Failed to import {module_name}, error: {e}")

    return imported_module

def print_module_info(module_class, module_name):
    """Prints general information on a given module under the category of it's respective
    category.
    
    :param module_class: The type of module we will be verifying support for. This
        is different than the module name itself. This is the category of module.
    :type module_class: str

    :param module_name: The name of the module, this would be the module being called
    :type module_name: str

    :return: Nothing, prints and exits application upon completion
    :rtype: None
    """

    module_object = check_module_support(module_class, module_name) #include_subdirs)
    if (module_object == None):
        exit(-1)

    print("\nUsage information for %s\n" % (module_name))
    if (module_class == "modules"):
        m = module_object.Module
    elif (module_class == "payloads"):
        m = module_object.Shellcode
    else:
        sys.exit(f"Invalid module class: {module_class}")

    # The description of the module overall
    try:
        print("{}{}".format("Name: ".rjust(20), m.name))
        print("{}{}".format("Module: ".rjust(20), m.module))
        print("{}{}".format("Architecture: ".rjust(20), m.arch))
        print("{}{}".format("Platform: ".rjust(20), m.platform))
        print("{}{}".format("Ring: ".rjust(20), m.ring))
    except:
        pass        


    print("\nAuthor(s):")
    for i in range(len(m.author)):
        print("".rjust(4) + m.author[i])

    print("\nTested against:")
    for i in range(len(m.tested_platforms)):
        print("".rjust(4) + m.tested_platforms[i])
    print("")

    # Information on each argument for a given module and what it does
    mod_args = m.arguments
    if (mod_args != None):

        # Calculate the largest lines as this will affect how the infromation is presented
        max_arg_name = 0x0D
        max_arg_info = 0x00
       
        for arg_name in mod_args.keys():
            arg_name_size = len(arg_name)
            arg_info_size = len(mod_args[arg_name]['description'])
            
            if arg_name_size > max_arg_name:
                max_arg_name = arg_name_size

            if arg_info_size > max_arg_info:
                max_arg_info = arg_info_size

        # Print the argument information with the calculation complete
        print("Argument Information\n")
        print(f"  {'Name':<{max_arg_name}} {'Description':<{max_arg_info}} {'Optional'}")
        print(f"  {'-':->{max_arg_name}} {'-':-<{max_arg_info}} {'--------'}")
        
        for arg_name, _ in mod_args.items():
            optional = mod_args[arg_name]["optional"]
            description = mod_args[arg_name]["description"]
            print(f"  {arg_name:<{max_arg_name}} {description:<{max_arg_info}} {optional:>8}")
        print("")

        if ("options" in mod_args[arg_name].keys()):


            # Once again calc sizes
            max_option_size = 0x0D
            max_info_size = 0x00
            supported_options = mod_args[arg_name]['options']
            for option, info in supported_options.items():
                option_len = len(option)
                info_len = len(info)

                if info_len > max_info_size:
                    max_info_size = info_len
                if option_len > max_option_size:
                    max_option_size = option_len

            # print it
            print(f"Argument Options:\n")
            print(f"  {arg_name:<{max_option_size}} {'Description':{max_option_size}}")
            print(f"  {'-':-<{max_option_size}} {'-':-<{max_info_size}}")
            for opt, opt_desc in supported_options.items():
                print(f"  {opt:<{max_option_size}} {opt_desc}")
            print("")

    print("Description:")
    print(f"{''.rjust(4)}{m.description}")

    print("Example:\n")
    print(f"{''.rjust(4)}{m.example_run}\n")

    exit(0)

def argument_check(required_arguments, user_arguments):
    """This function is responsible for verifying the user has provided the arguments needed
    for a given module. On success a dictionary containing proper args will be returned - on
    failure None.

    :param required_arguments: This is a dictionary containing the arguments used by the module
    :type required_arguments: dict

    :param user_arguments: This is a dictionary containing the arguements provided by the user
    :type user_arguments: dict

    :return: A dictionary containing arguments to be used by the module
    :rtype: dict
    """

    optional_args = []
    expected_args = []
    args_found    = []
    final_dict    = {}
    missing_args  = ""
    fail_check    = 0

    for arg_name, _ in required_arguments.items():
        if (required_arguments[arg_name]["optional"] == "no"):
            expected_args += arg_name,
        optional_args += arg_name,

    try:
        for i in range(len(user_arguments)):
            user_arg = user_arguments[i].split('=')[0]
            user_var = user_arguments[i].split('=')[1]

            if (user_arg not in optional_args):
                continue
            else:
                args_found += user_arg,
                final_dict[user_arg] = user_var
    except:
        print("Error parsing arguments")
        sys.exit(-1)

    for i in range(len(expected_args)):
        if (expected_args[i] not in args_found):
            missing_args += f"{expected_args[i]}, "
            fail_check = 1

    if (fail_check == 1):
        print(f"Missing arguments: {missing_args.rstrip(', ')}")
        return None

    for fd_arg, fd_var in final_dict.items():
        if (len(fd_var) < 1):
            print("Empty arguments")
            sys.exit(-1)

    return final_dict
