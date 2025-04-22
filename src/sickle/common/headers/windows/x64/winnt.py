import ctypes

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
        ("DataDirectory",               _IMAGE_DATA_DIRECTORY),

    ]

class _IMAGE_NT_HEADERS64(ctypes.Structure):
    _fields_ = [
        ("Signature",      ctypes.c_int32),
        ("FileHeader",     _IMAGE_FILE_HEADER),
        ("OptionalHeader", _IMAGE_OPTIONAL_HEADER64),
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

class _IMAGE_IMPORT_BY_NAME(ctypes.Structure):
    _fields_ = [
        ("Hint", ctypes.c_int16),
        ("Name", ctypes.c_char * 1)
    ]
