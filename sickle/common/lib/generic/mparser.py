'''

mparser: Functions related to handling module arguments and generic module data should go here

'''

import os
import sys

###
# argument_check:
#   This function is resposible for verifying the user has provided the arguments needed for a given
#   module. On success a dictionary containing proper args will be returned - on failure None.
###
def argument_check(required_arguments, user_arguments):
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
