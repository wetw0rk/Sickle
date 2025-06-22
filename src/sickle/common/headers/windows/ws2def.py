from ctypes import c_char
from ctypes import c_uint16
from ctypes import Structure

class sockaddr(Structure):
    _fields_ = [
        ("sa_family", c_uint16),
        ("sa_data",   (c_char * 14)),
    ]

AF_UNSPEC       = 0
AF_UNIX         = 1
AF_INET         = 2
AF_IMPLINK      = 3
AF_PUP          = 4
AF_CHAOS        = 5
AF_NS           = 6
AF_IPX          = AF_NS
AF_ISO          = 7
AF_OSI          = AF_ISO
AF_ECMA         = 8
AF_DATAKIT      = 9
AF_CCITT        = 10
AF_SNA          = 11
AF_DECnet       = 12
AF_DLI          = 13
AF_LAT          = 14
AF_HYLINK       = 15
AF_APPLETALK    = 16
AF_NETBIOS      = 17
AF_VOICEVIEW    = 18
AF_FIREFOX      = 19
AF_UNKNOWN1     = 20
AF_BAN          = 21
AF_ATM          = 22
AF_INET6        = 23
AF_CLUSTER      = 24
AF_12844        = 25
AF_IRDA         = 26
AF_NETDES       = 28
AF_TCNPROCESS   = 29
AF_TCNMESSAGE   = 30
AF_ICLFXBM      = 31
AF_BTH          = 32
AF_LINK         = 33
AF_HYPERV       = 34
AF_MAX          = 35

IPPROTO_IP      = 0
IPPROTO_ICMP    = 1
IPPROTO_IGMP    = 2
IPPROTO_GGP     = 3
IPPROTO_IPV4    = 4
IPPROTO_TCP     = 6
IPPROTO_UDP     = 17
IPPROTO_IDP     = 22
IPPROTO_IPV6    = 41
IPPROTO_ICMPV6  = 58
IPPROTO_ND      = 77
IPPROTO_RAW     = 255
IPPROTO_MAX     = 256
