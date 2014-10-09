from .. import Packet, types, Field
from ..errors import *

class TCP(Packet):
    sport    = Field(types.UnsignedShort, default=0xdead)
    dport    = Field(types.UnsignedShort, default=0)
    seq      = Field(types.UnsignedInteger, default=0xdeadbeefL)
    ack      = Field(types.UnsignedInteger, default=0)
    off      = Field(types.UnsignedChar, default=((5 << 4) | 0))
    flags    = Field(types.UnsignedChar, default=0x02)
    win      = Field(types.UnsignedShort, default=65535)
    sum      = Field(types.UnsignedShort, default=0)
    urp      = Field(types.UnsignedShort, default=0)

    tcp_options = Field()

    def process(self):
        options_length = ((self.off >> 4) << 2) - self.__length__
        if options_length < 0:
            raise PacketProcessingError('TCP options length invalid')
        if options_length > 0:
            self.tcp_options = self.data[:options_length]
            self.data = self.data[options_length:]
