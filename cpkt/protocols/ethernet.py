from .. import Packet, types, Field

# Ethernet Types
ETH_TYPE_ARP            = 0x0806 # ARP
ETH_TYPE_IP             = 0x0800 # IP protocol
ETH_TYPE_IP6            = 0x86DD # IPv6 protocol

class Ethernet(Packet):
    eth_dst     = Field(types.String(6))
    eth_src     = Field(types.String(6))
    type        = Field(types.UnsignedShort, default=0x0800)
