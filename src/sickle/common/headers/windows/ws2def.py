##
# References:
#   https://github.com/wine-mirror/wine/blob/1d1e5fb3e51b2acb0143e86c16463dfed1bc90aa/include/ws2def.h
#
##

import ctypes

class sockaddr(ctypes.Structure):
    _fields_ = [
        ("sa_family", ctypes.c_uint16),
        ("sa_data",   (ctypes.c_char * 14)),
    ]

AF_UNSPEC        = 0
AF_UNIX          = 1
AF_INET          = 2
AF_IMPLINK       = 3
AF_PUP           = 4
AF_CHAOS         = 5
AF_NS            = 6
AF_IPX           = AF_NS
AF_ISO           = 7
AF_OSI           = AF_ISO
AF_ECMA          = 8
AF_DATAKIT       = 9
AF_CCITT         = 10
AF_SNA           = 11
AF_DECnet        = 12
AF_DLI           = 13
AF_LAT           = 14
AF_HYLINK        = 15
AF_APPLETALK     = 16
AF_NETBIOS       = 17
AF_VOICEVIEW     = 18
AF_FIREFOX       = 19
AF_UNKNOWN1      = 20
AF_BAN           = 21
AF_ATM           = 22
AF_INET6         = 23
AF_CLUSTER       = 24
AF_12844         = 25
AF_IRDA          = 26
AF_NETDES        = 28
AF_TCNPROCESS    = 29
AF_TCNMESSAGE    = 30
AF_ICLFXBM       = 31
AF_BTH           = 32
AF_LINK          = 33
AF_HYPERV        = 34
AF_MAX           = 35

WS_AF_UNSPEC     = 0
WS_AF_UNIX       = 1
WS_AF_INET       = 2
WS_AF_IMPLINK    = 3
WS_AF_PUP        = 4
WS_AF_CHAOS      = 5
WS_AF_NS         = 6
WS_AF_IPX        = WS_AF_NS
WS_AF_ISO        = 7
WS_AF_OSI        = WS_AF_ISO
WS_AF_ECMA       = 8
WS_AF_DATAKIT    = 9
WS_AF_CCITT      = 10
WS_AF_SNA        = 11
WS_AF_DECnet     = 12
WS_AF_DLI        = 13
WS_AF_LAT        = 14
WS_AF_HYLINK     = 15
WS_AF_APPLETALK  = 16
WS_AF_NETBIOS    = 17
WS_AF_VOICEVIEW  = 18
WS_AF_FIREFOX    = 19
WS_AF_UNKNOWN1   = 20
WS_AF_BAN        = 21
WS_AF_ATM        = 22
WS_AF_INET6      = 23
WS_AF_CLUSTER    = 24
WS_AF_12844      = 25
WS_AF_IRDA       = 26
WS_AF_NETDES     = 28
WS_AF_TCNPROCESS = 29
WS_AF_TCNMESSAGE = 30
WS_AF_ICLFXBM    = 31
WS_AF_BTH        = 32
WS_AF_LINK       = 33
WS_AF_HYPERV     = 34
WS_AF_MAX        = 35

IPPROTO_IP      = 0
WS_IPPROTO_IP   = 0

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

INADDR_ANY          = 0x00000000
INADDR_LOOPBACK     = 0x7f000001
INADDR_BROADCAST    = 0xffffffff
INADDR_NONE         = 0xffffffff

WS_INADDR_ANY       = 0x00000000
WS_INADDR_LOOPBACK  = 0x7f000001
WS_INADDR_BROADCAST = 0xffffffff
WS_INADDR_NONE      = 0xffffffff

IN_CLASSA_NSHIFT    = 24
IN_CLASSA_MAX       = 128
IN_CLASSA_NET       = 0xff000000
IN_CLASSA_HOST      = 0x00ffffff
IN_CLASSB_NSHIFT    = 16
IN_CLASSB_MAX       = 65536
IN_CLASSB_NET       = 0xffff0000
IN_CLASSB_HOST      = 0x0000ffff
IN_CLASSC_NSHIFT    = 8
IN_CLASSC_NET       = 0xffffff00
IN_CLASSC_HOST      = 0x000000ff

WS_IN_CLASSA_NSHIFT = 24
WS_IN_CLASSA_MAX    = 128
WS_IN_CLASSA_NET    = 0xff000000
WS_IN_CLASSA_HOST   = 0x00ffffff
WS_IN_CLASSB_NSHIFT = 16
WS_IN_CLASSB_MAX    = 65536
WS_IN_CLASSB_NET    = 0xffff0000
WS_IN_CLASSB_HOST   = 0x0000ffff
WS_IN_CLASSC_NSHIFT = 8
WS_IN_CLASSC_NET    = 0xffffff00
WS_IN_CLASSC_HOST   = 0x000000ff

SO_BSP_STATE                = 0x1009
SO_RANDOMIZE_PORT           = 0x3005
SO_PORT_SCALABILITY         = 0x3006
SO_REUSE_UNICASTPORT        = 0x3007
SO_REUSE_MULTICASTPORT      = 0x3008
TCP_NODELAY                 = 0x0001
WS_SO_BSP_STATE             = 0x1009
WS_SO_RANDOMIZE_PORT        = 0x3005
WS_SO_PORT_SCALABILITY      = 0x3006
WS_SO_REUSE_UNICASTPORT     = 0x3007
WS_SO_REUSE_MULTICASTPORT   = 0x3008
WS_TCP_NODELAY              = 0x0001
