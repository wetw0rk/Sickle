import ctypes

AF_UNSPEC = 0
AF_INET = 2
AF_IPX = 6
AF_APPLETALK = 16
AF_NETBIOS = 17
AF_INET6 = 23
AF_IRDA = 26
AF_BTH = 32

SOCK_STREAM = 1
SOCK_DGRAM = 2
SOCK_RAW = 3
SOCK_RDM = 4
SOCK_SEQPACKET = 5

IPPROTO_ICMP = 1
IPPROTO_IGMP = 2
BTHPROTO_RFCOMM = 3
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58
IPPROTO_RM = 113

class sockaddr(ctypes.Structure):
    _fields_ = [
        ("sa_family", ctypes.c_int16),
        ("sa_data",    (ctypes.c_char * 14)),
    ]
