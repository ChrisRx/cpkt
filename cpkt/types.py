import socket
import struct

class Field(object):
    def __new__(cls, field_format=None, default=None):
        if field_format is None:
            return BlankField()
        else:
            return BaseField(field_format, default)

class BaseField(object):
    __slots__ = ['name', 'field_format', 'formatter', 'default', '__order__',
        '__type__']
    __type__ = 'field'
    creation_counter = 0

    def __init__(self, field_format=None, default=None):
        if isinstance(field_format, type):
            self.field_format = field_format()
        else:
            self.field_format = field_format
        self.__order__ = BaseField.creation_counter
        self.formatter = None
        self.default = default
        BaseField.creation_counter += 1

    def __repr__(self):
        return "<Field '{0}'>".format(self.name)

class BlankField(str):
    __type__ = 'blank'

class MacField(Field):
    def __init__(self, field_format=None, default=None):
        super(MacField, self).__init__(field_format=field_format,
            default=default)
        self.formatter = self.format_mac_address

    @staticmethod
    def format_mac_address(address):
        return ":".join([address.encode('hex')[i:i+2]
            for i in range(0, 12, 2)])

class IPAddressField(Field):
    def __init__(self, field_format=None, default=None):
        super(IPAddressField, self).__init__(field_format=field_format,
            default=default)
        self.formatter = self.format_ip_address

    @staticmethod
    def format_ip_address(address):
        return socket.inet_ntoa(address)

class BinaryFormat(object):
    __slots__ = ('byte_order', 'length', 'code')
    def __init__(self, byte_order=">", length=0, code=None):
        self.byte_order = byte_order
        self.length = length
        self.code = code

    def calcsize(self):
        return struct.calcsize("{0}{1}".format(self.byte_order,
            self.__repr__()))

    @property
    def format_string(self):
        return self.__repr__()

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "{0}{1}".format(self.length, self.code)

class String(BinaryFormat):
    # __slots__ = BinaryFormat.__slots__
    def __init__(self, length=1, code="s"):
        super(String, self).__init__(length=length, code=code)

class UnsignedShort(BinaryFormat):
    # __slots__ = BinaryFormat.__slots__
    def __init__(self, length=1, code="H"):
        super(UnsignedShort, self).__init__(length=length, code=code)

class UnsignedInteger(BinaryFormat):
    # __slots__ = BinaryFormat.__slots__
    def __init__(self, length=1, code="I"):
        super(UnsignedInteger, self).__init__(length=length, code=code)

class UnsignedChar(BinaryFormat):
    # __slots__ = BinaryFormat.__slots__
    def __init__(self, length=1, code="B"):
        super(UnsignedChar, self).__init__(length=length, code=code)


class NULL(object):
    __slots__ = ['length']
    def __init__(self, length=1):
        self.length = length

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "\x00" * self.length
