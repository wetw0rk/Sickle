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
