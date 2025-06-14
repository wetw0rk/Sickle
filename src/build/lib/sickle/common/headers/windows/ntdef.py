import ctypes

from sickle.common.lib.reversing.smartarch import get_ptr

class _RTL_BALANCED_NODE(ctypes.Structure):
    class _CHILDREN_UNION(ctypes.Union):
        class _DUMMYSTRUCTNAME(ctypes.Structure):
            _fields_ = [
                ("Left", ctypes.c_void_p),
                ("Right", ctypes.c_void_p),
            ]
        _fields_ = [
            ("Children", ctypes.c_void_p * 2),
            ("DUMMYSTRUCTNAME", _DUMMYSTRUCTNAME),
        ]

    class _BALANCE_UNION(ctypes.Union):
        _fields_ = [
            ("ParentValue", ctypes.c_size_t),
            ("_bitfield", ctypes.c_ubyte),
        ]

    _anonymous_ = ("DUMMYUNIONNAME", "DUMMYUNIONNAME2")
    _fields_ = [
        ("DUMMYUNIONNAME", _CHILDREN_UNION),
        ("DUMMYUNIONNAME2", _BALANCE_UNION),
    ]

class _LIST_ENTRY(ctypes.Structure):
    _fields_ = [
        ("Flink", get_ptr()),
        ("Blink", get_ptr()),
    ]

class _UNICODE_STRING(ctypes.Structure):
    _fields_ = [
        ("Length",          ctypes.c_uint16),   # USHORT
        ("MaximumLength",   ctypes.c_uint16),   # USHORT
        ("Buffer",          get_ptr()),             # PWSTR
    ]
