
from sickle.common.lib.reversing import smartarch

def get_win_prologue(op_as_func, stack_space):
    """This function will generate a generic function prologue based on the flags provided
    by the user.

    :param op_as_func: Determines if the prologue will operate as a normal function
    :type op_as_func: bool

    :param stack_space: The stack space to be used by the shellcode
    :type stack_space: int
    """

    stub = "_start:\n"

    if op_as_func == True:
        stub += """    push rbp
    mov rbp, rsp\n"""

    stub += f"    sub rsp, {stack_space}\n"

    if op_as_func == False:
        stub += "    and rsp, 0xfffffffffffffff0\n"

    stub += """    call getKernel32
    mov rdi, rax\n"""

    return stub

def get_win_epilogue(op_as_func, exit_technique, storage_offsets):
    """This function will generate a generic function epilogue based on the flags provided
    by the user.

    :param op_as_func: Determines if the prologue will operate as a normal function
    :type op_as_func: bool

    :param exit_technique: The technique to use when exiting the shellcode
    :type exit_technique: str

    :param storage_offsets: Dictionary object containing the storage offsets for
        a given target function.
    :type storage_offsets: dict
    """

    stub = ""

    if exit_technique == "thread":
        stub += f"""; RAX => RtlExitUserThread([in] DWORD dwExitCode); // RCX => 0
call_RtlExitUserThread:
    xor rcx, rcx
    mov rax, [rbp - {storage_offsets['RtlExitUserThread']}]
    call rax\n"""

    elif exit_technique == "process":
        stub += f"""; RAX => ExitProcess([in] UINT uExitCode); // RCX => 0
call_ExitProcess:
    xor rcx, rcx
    mov rax, [rbp - {storage_offsets['ExitProcess']}]
    call rax\n"""

    elif exit_technique == "terminate":
        stub += f"""; RAX => TerminateProcess([in] HANDLE hProcess,   // RCX => -1 (Current Process)
;                         [in] UINT   uExitCode); // RDX => 0x00 (Clean Exit)
call_TerminateProcess:
    xor rcx, rcx
    dec rcx
    xor rdx, rdx
    mov rax, [rbp - {storage_offsets['TerminateProcess']}]
    call rax\n"""
    
    if op_as_func == True:
        stub += """fin:
    leave
    ret

"""

    return stub
