from .cpkt import Packet
# from .pcap import Reader
from .types import Field
from . import pcap
from . import types

# from .types import MacField, IPAddressField, String, UnsignedShort, \
#   UnsignedInteger, UnsignedChar
#Reader = pcap.Reader
#Writer = pcap.Writer
from .pcap import Reader, Writer

__all__ = ['Packet', 'Field', 'Reader', 'pcap', 'types']
