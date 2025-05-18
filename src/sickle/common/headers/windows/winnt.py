import ctypes

PAGE_NOACCESS                           = 0x00000001
PAGE_READONLY                           = 0x00000002
PAGE_READWRITE                          = 0x00000004
PAGE_WRITECOPY                          = 0x00000008
PAGE_EXECUTE                            = 0x00000010
PAGE_EXECUTE_READ                       = 0x00000020
PAGE_EXECUTE_READWRITE                  = 0x00000040
PAGE_EXECUTE_WRITECOPY                  = 0x00000080
PAGE_GUARD                              = 0x00000100
PAGE_NOCACHE                            = 0x00000200
PAGE_WRITECOMBINE                       = 0x00000400
PAGE_GRAPHICS_NOACCESS                  = 0x00000800
PAGE_GRAPHICS_READONLY                  = 0x00001000
PAGE_GRAPHICS_READWRITE                 = 0x00002000
PAGE_GRAPHICS_EXECUTE                   = 0x00004000
PAGE_GRAPHICS_EXECUTE_READ              = 0x00008000
PAGE_GRAPHICS_EXECUTE_READWRITE         = 0x00010000
PAGE_GRAPHICS_COHERENT                  = 0x00020000
PAGE_GRAPHICS_NOCACHE                   = 0x00040000
PAGE_ENCLAVE_MASK                       = 0x10000000
PAGE_ENCLAVE_UNVALIDATED                = 0x20000000
PAGE_ENCLAVE_NO_CHANGE                  = 0x20000000
PAGE_TARGETS_NO_UPDATE                  = 0x40000000
PAGE_TARGETS_INVALID                    = 0x40000000
PAGE_REVERT_TO_FILE_MAP                 = 0x80000000
PAGE_ENCLAVE_THREAD_CONTROL             = 0x80000000
PAGE_ENCLAVE_DECOMMIT                   = (PAGE_ENCLAVE_MASK | 0)
PAGE_ENCLAVE_SS_FIRST                   = (PAGE_ENCLAVE_MASK | 1)
PAGE_ENCLAVE_SS_REST                    = (PAGE_ENCLAVE_MASK | 2)

MEM_COMMIT                              = 0x00001000
MEM_RESERVE                             = 0x00002000
MEM_REPLACE_PLACEHOLDER                 = 0x00004000
MEM_RESERVE_PLACEHOLDER                 = 0x00040000
MEM_RESET                               = 0x00080000
MEM_TOP_DOWN                            = 0x00100000
MEM_PHYSICAL                            = 0x00400000
MEM_RESET_UNDO                          = 0x10000000
MEM_LARGE_PAGES                         = 0x20000000


IMAGE_SCN_MEM_DISCARDABLE               = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED                = 0x04000000
IMAGE_SCN_MEM_NOT_PAGED                 = 0x08000000
IMAGE_SCN_MEM_SHARED                    = 0x10000000
IMAGE_SCN_MEM_EXECUTE                   = 0x20000000
IMAGE_SCN_MEM_READ                      = 0x40000000
IMAGE_SCN_MEM_WRITE                     = 0x80000000

IMAGE_REL_BASED_ABSOLUTE                = 0
IMAGE_REL_BASED_HIGH                    = 1
IMAGE_REL_BASED_LOW                     = 2
IMAGE_REL_BASED_HIGHLOW                 = 3
IMAGE_REL_BASED_HIGHADJ                 = 4
IMAGE_REL_BASED_MIPS_JMPADDR            = 5
IMAGE_REL_BASED_ARM_MOV32A              = 5
IMAGE_REL_BASED_ARM_MOV32               = 5
IMAGE_REL_BASED_SECTION                 = 6
IMAGE_REL_BASED_REL                     = 7
IMAGE_REL_BASED_ARM_MOV32T              = 7
IMAGE_REL_BASED_THUMB_MOV32             = 7
IMAGE_REL_BASED_MIPS_JMPADDR16          = 9
IMAGE_REL_BASED_IA64_IMM64              = 9
IMAGE_REL_BASED_DIR64                   = 10
IMAGE_REL_BASED_HIGH3ADJ                = 11

IMAGE_DIRECTORY_ENTRY_EXPORT            = 0
IMAGE_DIRECTORY_ENTRY_IMPORT            = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE          = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION         = 3
IMAGE_DIRECTORY_ENTRY_SECURITY          = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC         = 5
IMAGE_DIRECTORY_ENTRY_DEBUG             = 6
IMAGE_DIRECTORY_ENTRY_COPYRIGHT         = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR         = 8
IMAGE_DIRECTORY_ENTRY_TLS               = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      = 11
IMAGE_DIRECTORY_ENTRY_IAT               = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    = 14

class _LARGE_INTEGER(ctypes.Union):
    class _STRUCT(ctypes.Structure):
        _fields_ = [
            ("LowPart", ctypes.c_uint32),  # DWORD
            ("HighPart", ctypes.c_int32),  # LONG
        ]

    _anonymous_ = ("DUMMYSTRUCTNAME", "u")
    _fields_ = [
        ("DUMMYSTRUCTNAME", _STRUCT),
        ("u", _STRUCT),
        ("QuadPart", ctypes.c_int64),     # LONGLONG
    ]

class _ULARGE_INTEGER(ctypes.Union):
    class _STRUCT(ctypes.Structure):
        _fields_ = [
            ("LowPart",     ctypes.c_uint32), # DWORD
            ("HighPart",    ctypes.c_uint32), # DWORD
        ]

    _anonymous_ = ("DUMMYSTRUCTNAME", "u")
    _fields_ = [
        ("DUMMYSTRUCTNAME", _STRUCT),
        ("u", _STRUCT),
        ("QuadPart", ctypes.c_uint64),
    ]

class _IMAGE_DOS_HEADER(ctypes.Structure):
    _fields_ = [
        ("e_magic",      ctypes.c_int16),
        ("e_cblp",       ctypes.c_int16),
        ("e_cp",         ctypes.c_int16),
        ("e_crlc",       ctypes.c_int16),
        ("e_cparhdr",    ctypes.c_int16),
        ("e_minalloc",   ctypes.c_int16),
        ("e_maxalloc",   ctypes.c_int16),
        ("e_ss",         ctypes.c_int16),
        ("e_sp",         ctypes.c_int16),
        ("e_csum",       ctypes.c_int16),
        ("e_ip",         ctypes.c_int16),
        ("e_cs",         ctypes.c_int16),
        ("e_lfarlc",     ctypes.c_int16),
        ("e_ovno",       ctypes.c_int16),
        ("e_res",        ctypes.c_int16 * 4),
        ("e_oemid",      ctypes.c_int16),
        ("e_oeminfo",    ctypes.c_int16),
        ("e_res2",       ctypes.c_int16 * 10),
        ("e_lfanew",     ctypes.c_int32),
    ]

class _IMAGE_FILE_HEADER(ctypes.Structure):
    _fields_ = [
        ("Machine",              ctypes.c_int16),
        ("NumberOfSections",     ctypes.c_int16),
        ("TimeDateStamp",        ctypes.c_int32),
        ("PointerToSymbolTable", ctypes.c_int32),
        ("NumberOfSymbols",      ctypes.c_int32),
        ("SizeOfOptionalHeader", ctypes.c_int16),
        ("Characteristics",      ctypes.c_int16),
    ]

class _IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("VirtualAddress", ctypes.c_int32),
        ("Size",           ctypes.c_int32),
    ]

class _IMAGE_OPTIONAL_HEADER64(ctypes.Structure):
    _fields_ = [
        ("Magic",                       ctypes.c_int16),
        ("MajorLinkerVersion",          ctypes.c_byte),
        ("MinorLinkerVersion",          ctypes.c_byte),
        ("SizeOfCode",                  ctypes.c_int32),
        ("SizeOfInitializedData",       ctypes.c_int32),
        ("SizeOfUninitializedData",     ctypes.c_int32),
        ("AddressOfEntryPoint",         ctypes.c_int32),
        ("BaseOfCode",                  ctypes.c_int32),
        ("ImageBase",                   ctypes.c_uint64),
        ("SectionAlignment",            ctypes.c_int32),
        ("FileAlignment",               ctypes.c_int32),
        ("MajorOperatingSystemVersion", ctypes.c_int16),
        ("MinorOperatingSystemVersion", ctypes.c_int16),
        ("MajorImageVersion",           ctypes.c_int16),
        ("MinorImageVersion",           ctypes.c_int16),
        ("MajorSubsystemVersion",       ctypes.c_int16),
        ("MinorSubsystemVersion",       ctypes.c_int16),
        ("Win32VersionValue",           ctypes.c_int32),
        ("SizeOfImage",                 ctypes.c_int32),
        ("SizeOfHeaders",               ctypes.c_int32),
        ("CheckSum",                    ctypes.c_int32),
        ("Subsystem",                   ctypes.c_int16),
        ("DllCharacteristics",          ctypes.c_int16),
        ("SizeOfStackReserve",          ctypes.c_uint64),
        ("SizeOfStackCommit",           ctypes.c_uint64),
        ("SizeOfHeapReserve",           ctypes.c_uint64),
        ("SizeOfHeapCommit",            ctypes.c_uint64),
        ("LoaderFlags",                 ctypes.c_int32),
        ("NumberOfRvaAndSizes",         ctypes.c_int32),
        ("DataDirectory",               _IMAGE_DATA_DIRECTORY * 16),
    ]

class _IMAGE_NT_HEADERS64(ctypes.Structure):
    _fields_ = [
        ("Signature",      ctypes.c_int32),
        ("FileHeader",     _IMAGE_FILE_HEADER),
        ("OptionalHeader", _IMAGE_OPTIONAL_HEADER64),
    ]

class _IMAGE_OPTIONAL_HEADER(ctypes.Structure):
    _fields_ = [
        ("Magic",                       ctypes.c_int16),        # WORD
        ("MajorLinkerVersion",          ctypes.c_byte),         # BYTE
        ("MinorLinkerVersion",          ctypes.c_byte),         # BYTE
        ("SizeOfCode",                  ctypes.c_int32),        # DWORD
        ("SizeOfInitializedData",       ctypes.c_int32),        # DWORD
        ("SizeOfUninitializedData",     ctypes.c_int32),        # DWORD
        ("AddressOfEntryPoint",         ctypes.c_int32),        # DWORD
        ("BaseOfCode",                  ctypes.c_int32),        # DWORD
        ("BaseOfData",                  ctypes.c_int32),        # DWORD
        ("ImageBase",                   ctypes.c_int32),        # DWORD
        ("SectionAlignment",            ctypes.c_int32),        # DWORD
        ("FileAlignment",               ctypes.c_int32),        # DWORD
        ("MajorOperatingSystemVersion", ctypes.c_int16),        # WORD
        ("MinorOperatingSystemVersion", ctypes.c_int16),        # WORD
        ("MajorImageVersion",           ctypes.c_int16),        # WORD
        ("MinorImageVersion",           ctypes.c_int16),        # WORD
        ("MajorSubsystemVersion",       ctypes.c_int16),        # WORD
        ("MinorSubsystemVersion",       ctypes.c_int16),        # WORD
        ("Win32VersionValue",           ctypes.c_int32),        # DWORD
        ("SizeOfImage",                 ctypes.c_int32),        # DWORD
        ("SizeOfHeaders",               ctypes.c_int32),        # DWORD
        ("CheckSum",                    ctypes.c_int32),        # DWORD
        ("Subsystem",                   ctypes.c_int16),        # WORD
        ("DllCharacteristics",          ctypes.c_int16),        # WORD
        ("SizeOfStackReserve",          ctypes.c_int32),        # DWORD
        ("SizeOfStackCommit",           ctypes.c_int32),        # DWORD
        ("SizeOfHeapReserve",           ctypes.c_int32),        # DWORD
        ("SizeOfHeapCommit",            ctypes.c_int32),        # DWORD
        ("LoaderFlags",                 ctypes.c_int32),        # DWORD
        ("NumberOfRvaAndSizes",         ctypes.c_int32),        # DWORD
        ("DataDirectory",               _IMAGE_DATA_DIRECTORY), # IMAGE_DATA_DIRECTORY
    ]

class _IMAGE_NT_HEADERS(ctypes.Structure):
    _fields_ = [
        ("Signature",       ctypes.c_int32),        # DWORD
        ("FileHeader",      _IMAGE_FILE_HEADER),    # IMAGE_FILE_HEADER
        ("OptionalHeader", _IMAGE_OPTIONAL_HEADER), # IMAGE_OPTIONAL_HEADER32
    ]

# These are the settings of the Machine field.
IMAGE_SIZEOF_SHORT_NAME = 8

class _IMAGE_SECTION_HEADER(ctypes.Structure):
    class _Misc(ctypes.Union):
        _fields_ = [
            ("PhysicalAddress", ctypes.c_int32),
            ("VirtualSize",     ctypes.c_int32),
        ]

    _anonymous = ("Misc",)

    _fields_ = [
        ("Name",                 ctypes.c_byte * IMAGE_SIZEOF_SHORT_NAME),
        ("Misc",                 _Misc),
        ("VirtualAddress",       ctypes.c_int32),
        ("SizeOfRawData",        ctypes.c_int32),
        ("PointerToRawData",     ctypes.c_int32),
        ("PointerToRelocations", ctypes.c_int32),
        ("PointerToLinenumbers", ctypes.c_int32),
        ("NumberOfRelocations",  ctypes.c_int16),
        ("NumberOfLinenumbers",  ctypes.c_int16),
        ("Characteristics",      ctypes.c_int32),
    ]

class _IMAGE_DATA_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("VirtualAddress", ctypes.c_int32),
        ("Size",           ctypes.c_int32),
    ]

class _IMAGE_BASE_RELOCATION(ctypes.Structure):
    _fields_ = [
        ("VirtualAddress", ctypes.c_int32),
        ("SizeOfBlock",    ctypes.c_int32),
    ]

class _IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
    class _DUMMYUNIONNAME(ctypes.Union):
        _fields_ = [
            ("Characteristics",    ctypes.c_int32),
            ("OriginalFirstThunk", ctypes.c_int32),
        ]

    _anonymous = ("DUMMYUNIONNAME",)

    _fields_ = [
        ("DUMMYUNIONNAME", _DUMMYUNIONNAME),
        ("TimeDateStamp",  ctypes.c_int32),
        ("ForwarderChain", ctypes.c_int32),
        ("Name",           ctypes.c_int32),
        ("FirstThunk",     ctypes.c_int32),
    ]

class _IMAGE_THUNK_DATA64(ctypes.Structure):
    class _u1(ctypes.Union):
        _fields_ = [
            ("ForwarderString", ctypes.c_uint64),
            ("Function",        ctypes.c_uint64),
            ("Ordinal",         ctypes.c_uint64),
            ("AddressOfData",   ctypes.c_uint64),
        ]

    _anonymous = ("u1",)

    _fields_ = [
        ("u1", _u1),
    ]    

# Export module directory
class _IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
    _fields_ = [
        ("Characteristics",         ctypes.c_uint32), # DWORD
        ("TimeDateStamp",           ctypes.c_uint32), # DWORD
        ("MajorVersion",            ctypes.c_uint32), # WORD
        ("MinorVersion",            ctypes.c_uint16), # WORD
        ("Name",                    ctypes.c_uint32), # DWORD
        ("Base",                    ctypes.c_uint32), # DWORD
        ("NumberOfFunctions",       ctypes.c_uint32), # DWORD
        ("NumberOfNames",           ctypes.c_uint32), # DWORD
        ("AddressOfFunctions",      ctypes.c_uint32), # DWORD
        ("AddressOfNames",          ctypes.c_uint32), # DWORD
        ("AddressOfNameOrdinals",   ctypes.c_uint32), # DWORD
    ]

# Import name entry
class _IMAGE_IMPORT_BY_NAME(ctypes.Structure):
    _fields_ = [
        ("Hint", ctypes.c_int16),
        ("Name", ctypes.c_char * 1)
    ]
