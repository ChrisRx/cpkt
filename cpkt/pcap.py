import sys
import time

from . import Packet, types, Field

TCPDUMP_MAGIC = 0xa1b2c3d4L
PMUDPCT_MAGIC = 0xd4c3b2a1L

PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4

DLT_NULL               = 0
DLT_EN10MB             = 1
DLT_EN3MB              = 2
DLT_AX25               = 3
DLT_PRONET             = 4
DLT_CHAOS              = 5
DLT_IEEE802            = 6
DLT_ARCNET             = 7
DLT_SLIP               = 8
DLT_PPP                = 9
DLT_FDDI               = 10
DLT_PFSYNC             = 18
DLT_IEEE802_11         = 105
DLT_LINUX_SLL          = 113
DLT_PFLOG              = 117
DLT_IEEE802_11_RADIO   = 127

if sys.platform.find('openbsd') != -1:
    DLT_LOOP           = 12
    DLT_RAW            = 14
else:
    DLT_LOOP           = 108
    DLT_RAW            = 12

dltoff = { DLT_NULL:4, DLT_EN10MB:14, DLT_IEEE802:22, DLT_ARCNET:6,
           DLT_SLIP:16, DLT_PPP:4, DLT_FDDI:21, DLT_PFLOG:48, DLT_PFSYNC:4,
           DLT_LOOP:4, DLT_LINUX_SLL:16 }
dltoff = { DLT_NULL:4, DLT_EN10MB:14, DLT_IEEE802:22, DLT_ARCNET:6,
           DLT_SLIP:16, DLT_PPP:4, DLT_FDDI:21, DLT_PFLOG:48, DLT_PFSYNC:4,
           DLT_LOOP:4, DLT_LINUX_SLL:16 }

class PacketHeader(Packet):
    ts          = Field(types.UnsignedInteger, default=0)
    ts_sec      = Field(types.UnsignedInteger, default=0)
    cap_len     = Field(types.UnsignedInteger, default=0)
    p_len       = Field(types.UnsignedInteger, default=0)

    def process(self):
        self.ts = (self.ts + (self.ts_sec / 1000000.0))

class FileHeader(Packet):
    magic       = Field(types.UnsignedInteger, default=TCPDUMP_MAGIC)
    v_major     = Field(types.UnsignedShort, default=PCAP_VERSION_MAJOR)
    v_minor     = Field(types.UnsignedShort, default=PCAP_VERSION_MINOR)
    thiszone    = Field(types.UnsignedInteger, default=0)
    sigfigs     = Field(types.UnsignedInteger, default=0)
    snaplen     = Field(types.UnsignedInteger, default=65535)
    linktype    = Field(types.UnsignedInteger, default=1)

    def set_link_type(self):
        if self.linktype in dltoff:
            return dltoff[self.linktype]
        else:
            return 0

class LittleEndianFileHeader(FileHeader):
    __byte_order__ = '<'

class BigEndianFileHeader(FileHeader):
    __byte_order__ = '>'

class LittleEndianPacketHeader(PacketHeader):
    __byte_order__ = '<'

class BigEndianPacketHeader(PacketHeader):
    __byte_order__ = '>'


class Writer(object):
    """Simple pcap dumpfile writer."""
    def __init__(self, file_name, snaplen=1500, linktype=DLT_EN10MB):
        self.file_handle = open(file_name, 'wb')
        if sys.byteorder == 'big':
            self.file_header = BigEndianFileHeader()
            self.packet_header = BigEndianPacketHeader
        else:
            self.file_header = LittleEndianFileHeader()
            self.packet_header = LittleEndianPacketHeader
        self.file_handle.write(self.file_header.pack())

    def write_packet(self, packet, packet_ts=None):
        if packet_ts is None:
            packet_ts = time.time()
        data = packet.pack()
        ts = int(packet_ts)
        ts_sec = round((float(packet_ts) - int(packet_ts)) * 1000000.0, 0)
        packet_header = self.packet_header(
            ts=ts,
            ts_sec=ts_sec,
            cap_len=len(data),
            p_len=len(data),
        )

        self.file_handle.write(packet_header.pack())
        self.file_handle.write(data)

    def close(self):
        self.file_handle.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.close()


class Reader(object):
    def __init__(self, file_name):
        self.file_handle = open(file_name, 'rb')
        self.name = self.file_handle.name
        self.file_descriptor = self.file_handle.fileno()
        file_header = self.file_handle.read(FileHeader.__length__)
        self.file_header = FileHeader(file_header)
        self.packet_header = PacketHeader
        if self.file_header.magic == PMUDPCT_MAGIC:
            self.file_header = LittleEndianFileHeader(file_header)
            self.packet_header = LittleEndianPacketHeader
        elif self.file_header.magic == TCPDUMP_MAGIC:
            self.file_header = BigEndianFileHeader(file_header)
            self.packet_header = BigEndianPacketHeader
        else:
            raise Exception("invalid TCPDUMP file header")
        self.dloff = self.file_header.set_link_type()

    def fileno(self):
        return self.file_descriptor

    @property
    def offset(self):
        return self.file_handle.tell()

    def datalink(self):
        return self.file_header.linktype

    def setfilter(self, value, optimize=1):
        return NotImplementedError

    def readpkts(self):
        return NotImplementedError

    def dispatch(self, cnt, callback, *args):
        return NotImplementedError

    def loop(self, callback, *args):
        return NotImplementedError

    def __iter__(self):
        self.file_handle.seek(FileHeader.__length__)
        while 1:
            data = self.file_handle.read(PacketHeader.__length__)
            if not data:
                break
            header = self.packet_header(data)
            data = self.file_handle.read(header.cap_len)
            yield (header.ts, data)

    def close(self):
        self.file_handle.close()

    def __enter__(self):
        return self

    def __exit__(self, type, value, tb):
        self.close()
