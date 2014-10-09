from .. import Packet, types, Field

IP_PROTO_IP  = 0
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

IP_PROTO_HOPOPTS        = 0
IP_PROTO_ROUTING        = 43
IP_PROTO_FRAGMENT       = 44
IP_PROTO_AH             = 51
IP_PROTO_ESP            = 50
IP_PROTO_DSTOPTS        = 60

class IP(Packet):
    v_hl    = Field(types.UnsignedChar, default=(4 << 4) | (20 >> 2))
    tos     = Field(types.UnsignedChar, default=0)
    len     = Field(types.UnsignedShort, default=20)
    id      = Field(types.UnsignedShort, default=0)
    off     = Field(types.UnsignedShort, default=0)
    ttl     = Field(types.UnsignedChar, default=64)
    p       = Field(types.UnsignedChar, default=0)
    sum     = Field(types.UnsignedShort, default=0)
    src     = Field(types.String(4), default=types.NULL(4))
    dst     = Field(types.String(4), default=types.NULL(4))

class IP6(Packet):
    v_fc_flow   = Field(types.UnsignedInteger, default=0x60000000L)
    plen        = Field(types.UnsignedShort, default=0)
    nxt         = Field(types.UnsignedChar, default=0)
    hlim        = Field(types.UnsignedChar, default=0)
    src         = Field(types.String(16), default=None)
    dst         = Field(types.String(16), default=None)

    def process(self):
        ext_data = self.data[:self.plen]
        next_ext = self.nxt

        while (next_ext in EXTENSION_HEADERS.keys()):
            ext = EXTENSION_HEADERS[next_ext](ext_data)
            ext_data = ext_data[ext.length:]
            next_ext = ext.nxt
        self.p = next_ext

class IP6Extension(Packet):
    pass

class IP6Options(IP6Extension):
    nxt         = Field(types.UnsignedChar, default=0)
    len         = Field(types.UnsignedChar, default=0)

    def process(self):
        self.options = []
        index = 0
        while (index < ((self.len + 1) * 8) - 2):
            opt_type = ord(self.data[index])

            if opt_type == 0:
                index += 1
                continue;
            opt_length = ord(self.data[index + 1])

            if opt_type == 1:
                index += opt_length + 2
                continue
            self.options.append({
              'type': opt_type,
              'opt_length': opt_length,
              'data': self.data[index + 2:index + 2 + opt_length]
            })

            index += opt_length + 2

class IP6HopOptions(IP6Options): pass

class IP6DstOptions(IP6Options): pass

class IP6Routing(IP6Extension):
    nxt             = Field(types.UnsignedChar, default=0)
    len             = Field(types.UnsignedChar, default=0)
    type            = Field(types.UnsignedChar, default=0)
    segs_left       = Field(types.UnsignedChar, default=0)
    rsvd_sl_bits    = Field(types.UnsignedInteger, default=0)

    def process(self):
        buf = buf[8:8 + self.len / 2 * 16]
        self.length = (self.len * 8) + 8
        self.addresses = [buf[i * addr_size: i * addr_size + addr_size]
            for i in range(self.len / 2)]
        self.data = buf

class IP6Fragment(IP6Extension):
    nxt             = Field(types.UnsignedChar, default=0)
    resv            = Field(types.UnsignedChar, default=0)
    frag_off_resv_m = Field(types.UnsignedShort, default=0)
    id              = Field(types.UnsignedInteger, default=0)

class IP6AH(IP6Extension):
    nxt             = Field(types.UnsignedChar, default=0)
    len             = Field(types.UnsignedChar, default=0)
    resv            = Field(types.UnsignedShort, default=0)
    spi             = Field(types.UnsignedInteger, default=0)
    seq             = Field(types.UnsignedInteger, default=0)

class IP6ESP(IP6Extension):
    pass

EXTENSION_HEADERS = {
    IP_PROTO_HOPOPTS: IP6HopOptions,
    IP_PROTO_ROUTING: IP6Routing,
    IP_PROTO_FRAGMENT: IP6Fragment,
    IP_PROTO_ESP: IP6ESP,
    IP_PROTO_AH: IP6AH,
    IP_PROTO_DSTOPTS: IP6DstOptions
}
