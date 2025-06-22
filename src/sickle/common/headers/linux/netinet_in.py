from ctypes import c_char
from ctypes import c_uint16
from ctypes import Structure

IPPROTO_IP       = 0   # Dummy protocol for TCP.  */
IPPROTO_ICMP     = 1   # Internet Control Message Protocol.  */
IPPROTO_IGMP     = 2   # Internet Group Management Protocol. */
IPPROTO_IPIP     = 4   # IPIP tunnels (older KA9Q tunnels use 94).  */
IPPROTO_TCP      = 6   # Transmission Control Protocol.  */
IPPROTO_EGP      = 8   # Exterior Gateway Protocol.  */
IPPROTO_PUP      = 12  # PUP protocol.  */
IPPROTO_UDP      = 17  # User Datagram Protocol.  */
IPPROTO_IDP      = 22  # XNS IDP protocol.  */
IPPROTO_TP       = 29  # SO Transport Protocol Class 4.  */
IPPROTO_DCCP     = 33  # Datagram Congestion Control Protocol.  */
IPPROTO_IPV6     = 41  # IPv6 header.  */
IPPROTO_RSVP     = 46  # Reservation Protocol.  */
IPPROTO_GRE      = 47  # General Routing Encapsulation.  */
IPPROTO_ESP      = 50  # encapsulating security payload.  */
IPPROTO_AH       = 51  # authentication header.  */
IPPROTO_MTP      = 92  # Multicast Transport Protocol.  */
IPPROTO_BEETPH   = 94  # IP option pseudo header for BEET.  */
IPPROTO_ENCAP    = 98  # Encapsulation Header.  */
IPPROTO_PIM      = 103 # Protocol Independent Multicast.  */
IPPROTO_COMP     = 108 # Compression Header Protocol.  */
IPPROTO_L2TP     = 115 # Layer 2 Tunnelling Protocol.  */
IPPROTO_SCTP     = 132 # Stream Control Transmission Protocol.  */
IPPROTO_UDPLITE  = 136 # UDP-Lite protocol.  */
IPPROTO_MPLS     = 137 # MPLS in IP.  */
IPPROTO_ETHERNET = 143 # Ethernet-within-IPv6 Encapsulation.  */
IPPROTO_RAW      = 255 # Raw IP packets.  */
IPPROTO_SMC      = 256 # Shared Memory Communications.  */
IPPROTO_MPTCP    = 262 # Multipath TCP connection.  */

class sockaddr(Structure):
    _fields_ = [
        ("sa_family_t", c_uint16),
        ("sa_data", (c_char * 14)),
    ]
