import ctypes

# TODO: use PTR to initialize functions 
from sickle.common.lib.reversing.smartarch import PTR


# TODO: Try to use PTR
def gen_offsets(sc_args, arch):
    """This function generates the offsets to be used within the shellcode. If
    the argument IS NOT 0x00 this function will assume the argument is dynamic
    and uses up space (aka will affect the offset).
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
    if arch == 'x86':
        arch_ptr_size = ctypes.sizeof(ctypes.c_uint32) # TODO USE PTR
        arg_start = 0x08
    elif (arch == 'x64'):
        arch_ptr_size = ctypes.sizeof(ctypes.c_uint64) # TODO USE PTR
        arg_start = ctypes.sizeof(ctypes.c_uint64) # TODO USE PTR

    for var in sc_args:
        alloc_space = sc_args[var]
        sc_args[var] = arg_start

        if alloc_space > 0x00:
            space_used = sc_args[var]
            arg_start += alloc_space
        else:
            arg_start += arch_ptr_size

    return sc_args
        
# TODO: Ensure works with x64
def calc_stack_space(sc_args, max_space):
    """This function will get the number of arguments being used by a shellcode
    stub. Since sickle supports multiple architectures, the maximum register
    size must be provided by the caller.

    :param sc_args: Shellcode arguments used by a shellcode module
    :type sc_args: dict

    :param max_space: The most amount of bytes a register can hold in the architecture
    :type max_space: int

    :return: Stack space needed for argument storage
    :rtype: int
    """

    # Initialize the space needed by the shellcode
    space_needed = 0x08

    # Since arguments work in the for of "pointers" we
    sc_argc = len(sc_args)
    if (sc_argc > 1):
        space_needed += sc_argc * max_space

    # If the shellcode argument has defined a size, it likely means that the user
    # wants that argument to work as a dynamic variable like a string. This means
    # we must allocate enough space to hold the string starting at said location.
    for var in sc_args:
        if sc_args[var] > 0x00:
            space_needed += sc_args[var]

    while ((space_needed % 16) != 0):
        space_needed += 0x08

    return space_needed

# TODO: Test on x64
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
