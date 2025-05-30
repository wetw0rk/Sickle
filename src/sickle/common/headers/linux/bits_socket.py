# Types of sockets.
SOCK_STREAM = 1 # Sequenced, reliable, connection-based
                # byte streams.

SOCK_DGRAM = 2 # Connectionless, unreliable datagrams
               # of fixed maximum length.

SOCK_RAW = 3 # Raw protocol interface.

SOCK_RDM = 4 # Reliably-delivered messages

SOCK_SEQPACKET = 5 # Sequenced, reliable, connection-based,
                   # datagrams of fixed maximum length.

SOCK_DCCP = 6 # Datagram Congestion Control Protocol.

SOCK_PACKET = 10 # Linux specific way of getting packets
                 # at the dev level.  For writing rarp and
                 # other similar things on the user level.

# Flags to be ORed into the type parameter of socket and socketpair and
# used for the flags parameter of paccept.

SOCK_CLOEXEC = 2000000 # Atomically set close-on-exec flag for the
                       # new descriptor(s).

SOCK_NONBLOCK = 4000 # Atomically mark descriptor(s) as
                     # non-blocking.

# Protocol families.
PF_UNSPEC	    = 0           # Unspecified.
PF_LOCAL	    = 1           # Local to host (pipes and file-domain).
PF_UNIX		    = PF_LOCAL    # POSIX name for PF_LOCAL.
PF_FILE		    = PF_LOCAL    # Another non-standard name for PF_LOCAL.
PF_INET		    = 2	          # IP protocol family.
PF_AX25		    = 3	          # Amateur Radio AX.25.
PF_IPX		    = 4	          # Novell Internet Protocol.
PF_APPLETALK	= 5	          # Appletalk DDP.
PF_NETROM	    = 6	          # Amateur radio NetROM.
PF_BRIDGE	    = 7	          # Multiprotocol bridge.
PF_ATMPVC	    = 8	          # ATM PVCs.
PF_X25		    = 9	          # Reserved for X.25 project.
PF_INET6	    = 10	      # IP version 6.
PF_ROSE		    = 11	      # Amateur Radio X.25 PLP.
PF_DECnet	    = 12	      # Reserved for DECnet project.
PF_NETBEUI	    = 13	      # Reserved for 802.2LLC project.
PF_SECURITY	    = 14	      # Security callback pseudo AF.
PF_KEY		    = 15	      # PF_KEY key management API.
PF_NETLINK	    = 16
PF_ROUTE	    = PF_NETLINK  # Alias to emulate 4.4BSD.
PF_PACKET	    = 17	      # Packet family. 
PF_ASH		    = 18	      # Ash. 
PF_ECONET	    = 19	      # Acorn Econet.
PF_ATMSVC	    = 20	      # ATM SVCs.
PF_RDS		    = 21	      # RDS sockets.
PF_SNA		    = 22	      # Linux SNA Project
PF_IRDA		    = 23	      # IRDA sockets.
PF_PPPOX	    = 24	      # PPPoX sockets.
PF_WANPIPE	    = 25	      # Wanpipe API sockets.
PF_LLC		    = 26	      # Linux LLC.
PF_IB		    = 27	      # Native InfiniBand address.
PF_MPLS		    = 28	      # MPLS.
PF_CAN		    = 29	      # Controller Area Network.
PF_TIPC		    = 30	      # TIPC sockets.
PF_BLUETOOTH	= 31	      # Bluetooth sockets.
PF_IUCV		    = 32	      # IUCV sockets.
PF_RXRPC	    = 33	      # RxRPC sockets.
PF_ISDN		    = 34	      # mISDN sockets.
PF_PHONET	    = 35	      # Phonet sockets.
PF_IEEE802154	= 36	      # IEEE 802.15.4 sockets.
PF_CAIF		    = 37	      # CAIF sockets.
PF_ALG		    = 38	      # Algorithm sockets.
PF_NFC		    = 39	      # NFC sockets.
PF_VSOCK	    = 40	      # vSockets.
PF_KCM		    = 41	      # Kernel Connection Multiplexor.
PF_QIPCRTR	    = 42	      # Qualcomm IPC Router.
PF_SMC		    = 43	      # SMC sockets.
PF_XDP		    = 44	      # XDP sockets.
PF_MAX		    = 45	      # For now..

# Address families.
AF_UNSPEC       = PF_UNSPEC
AF_LOCAL	    = PF_LOCAL
AF_UNIX		    = PF_UNIX
AF_FILE		    = PF_FILE
AF_INET		    = PF_INET
AF_AX25		    = PF_AX25
AF_IPX		    = PF_IPX
AF_APPLETALK    = PF_APPLETALK
AF_NETROM	    = PF_NETROM
AF_BRIDGE	    = PF_BRIDGE
AF_ATMPVC	    = PF_ATMPVC
AF_X25		    = PF_X25
AF_INET6	    = PF_INET6
AF_ROSE		    = PF_ROSE
AF_DECnet	    = PF_DECnet
AF_NETBEUI	    = PF_NETBEUI
AF_SECURITY	    = PF_SECURITY
AF_KEY		    = PF_KEY
AF_NETLINK	    = PF_NETLINK
AF_ROUTE	    = PF_ROUTE
AF_PACKET	    = PF_PACKET
AF_ASH		    = PF_ASH
AF_ECONET	    = PF_ECONET
AF_ATMSVC	    = PF_ATMSVC
AF_RDS		    = PF_RDS
AF_SNA		    = PF_SNA
AF_IRDA		    = PF_IRDA
AF_PPPOX	    = PF_PPPOX
AF_WANPIPE	    = PF_WANPIPE
AF_LLC		    = PF_LLC
AF_IB		    = PF_IB
AF_MPLS		    = PF_MPLS
AF_CAN		    = PF_CAN
AF_TIPC		    = PF_TIPC
AF_BLUETOOTH	= PF_BLUETOOTH
AF_IUCV		    = PF_IUCV
AF_RXRPC	    = PF_RXRPC
AF_ISDN		    = PF_ISDN
AF_PHONET	    = PF_PHONET
AF_IEEE802154	= PF_IEEE802154
AF_CAIF		    = PF_CAIF
AF_ALG		    = PF_ALG
AF_NFC		    = PF_NFC
AF_VSOCK	    = PF_VSOCK
AF_KCM		    = PF_KCM
AF_QIPCRTR	    = PF_QIPCRTR
AF_SMC		    = PF_SMC
AF_XDP		    = PF_XDP
AF_MAX		    = PF_MAX
