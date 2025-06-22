import ctypes

from sickle.common.lib.reversing import smartarch

def gen_offsets(sc_args):
    """This function generates the offsets to be used within the shellcode. If
    the argument IS NOT 0x00 this function will assume the argument is dynamic
    and uses up space (aka will affect the offset).

    :param sc_args: Shellcode arguments used by a shellcode module
    :type sc_args: dict

    :return: Updated sc_args object containing offsets for storage
    :rtype: dict
    """

    # Depending on what architecture we're working with it will affect where
    # offset storage can instantiated.
    #
    # x86
    #   [EBP+0x00] - Saved EBP
    #   [EBP+0x04] - Return address
    # x64
    #   [RSP+0x00] - Return address
    #   [RSP+....] - Shadow space
    #   [RSP+0x20] - ^ 
    #
    # It's important to note a big assumption is made below. For windows
    # and Linux this should be fine. However other OS's may need less or
    # more in terms of where arguments should be stored in memory from
    # the base pointer.
    arch_ptr_size = ctypes.sizeof(smartarch.get_ptr())
    arg_start = 0x08

    for var in sc_args:
        alloc_space = sc_args[var]
        sc_args[var] = arg_start

        if alloc_space > 0x00:
            arg_start += alloc_space
            sc_args[var] += alloc_space - arch_ptr_size
        else:
            arg_start += arch_ptr_size

    return sc_args

def calc_stack_space(sc_args):
    """This function will get the number of arguments being used by a shellcode
    stub. Since sickle supports multiple architectures, the maximum register
    size must be provided by the caller.

    :param sc_args: Shellcode arguments used by a shellcode module
    :type sc_args: dict

    :return: Stack space needed for argument storage
    :rtype: int
    """

    # Obtain the architecture and allocate the stack space based on the particular
    # architectures needs.
    max_space = ctypes.sizeof(smartarch.get_ptr())
    
    # If using x64 account for shadow space
    if smartarch.arch_used == 'x64':
        additional_space = 0x20
    else:
        additional_space = 0x00

    # Initialize the space needed by the shellcode
    space_needed = 0x08

    # Since arguments work in the form of "pointers" we
    sc_argc = len(sc_args)
    if (sc_argc > 1):
        space_needed += sc_argc * max_space

    # If the shellcode argument has defined a size, it likely means that the user
    # wants that argument to work as a dynamic variable like a string. This means
    # we must allocate enough space to hold the string starting at said location.
    for var in sc_args:
        if sc_args[var] > 0x00:
            space_needed += sc_args[var]

    space_needed += additional_space
    while ((space_needed % 16) != 0):
        space_needed += 0x01

    return space_needed

def init_sc_args(dependencies):
    """Initializes the arguments that are going to be used by the shellcode.

    :param dependencies: Object containing dependencies used
    "type dependencies: dict

    :return: List of functions used by the shellcode
    :rtype: list
    """

    # Extract ONLY functions from the dependencies
    used_funcs = []
    for lib, functions in dependencies.items():
        used_funcs.extend(functions)


    # Initialize all functions to 0x00 since the max storage used by this "arg"
    # will only be that of a pointer. 
    sc_args = {}
    for funk in range(len(used_funcs)):
        sc_args[used_funcs[funk]] = 0x00

    # Append the "functionName" key since resolved dependencies need space for the
    # string that will be used. We set it to 0x20 and not 0x00 so 
    #
    # TODO: Make dynamic and force space to be largest string % 8
    sc_args["functionName"] = 0x20

    return sc_args
