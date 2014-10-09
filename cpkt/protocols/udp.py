from .. import Packet, types, Field

class UDP(Packet):
    sport    = Field(types.UnsignedShort, default=0xdead)
    dport    = Field(types.UnsignedShort, default=0)
    ulen      = Field(types.UnsignedShort, default=0)
    sum      = Field(types.UnsignedShort, default=0)
