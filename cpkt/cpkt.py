import logging
import copy
import struct
import itertools

class MetaPacket(type):
    def __new__(cls, name, bases, attrs):
        ordered_fields = []
        slots = []
        for k, v in attrs.items():
            class_type = getattr(v, '__type__', None)
            if class_type == 'field':
                setattr(v, 'name', k)
                ordered_fields.append((v.__order__, v))
            if class_type == 'blank':
                slots.append(k)
        if ordered_fields:
            attrs['__fields__'] = [y for (x,y) in sorted(ordered_fields)]
            attrs['__length__'] = sum([x.field_format.calcsize()
                for x in attrs['__fields__']])
            attrs['__format__'] = [str(x.field_format)
                for x in attrs['__fields__']]
            attrs['__names__'] = [x.name for x in attrs['__fields__']]
            attrs['__defaults__'] = { x.name: x.default
                for x in attrs['__fields__']
                if x.default is not None}
            attrs['__slots__'] = attrs['__names__'] + \
                ['data', 'previous' 'extra'] + slots
            attrs['__blanks__'] = [x for x in slots]
            if attrs.get('__byte_order__', None) is None:
                attrs['__byte_order__'] = '>'
        return super(MetaPacket, cls).__new__(cls, name, bases, attrs)

class Packet(object):
    __metaclass__ = MetaPacket
    def __init__(self, *args, **kwargs):
        self.previous = []
        if args:
            packet = args[0]
            if isinstance(packet, str):
                data = packet
            elif isinstance(packet, tuple):
                # Assuming ts, data tuple? Probably should rethink this
                data = packet[1]
            elif isinstance(packet, Packet):
                data = packet.data
                self.previous = [p for p in packet.previous]
                self.previous.append(packet)
                setattr(self, packet.__class__.__name__.lower(), packet)
            formats = "{0}{1}".format(self.__byte_order__,
                "".join(self.__format__))
            values = data[0:self.__length__]
            for k, v in itertools.izip(self.__names__,
                struct.unpack(formats, values)):
                setattr(self, k, v)
            self.data = data[self.__length__:]
        else:
            for k in self.__defaults__:
                if self.__defaults__[k] == 0:
                    test = copy.copy(self.__defaults__[k])
                setattr(self, k, copy.copy(self.__defaults__[k]))
            for k, v in kwargs.iteritems():
                setattr(self, k, v)
            if getattr(self, 'data', None) is None:
                self.data = ""
        self.process()

    def process(self):
        """
        Overide method to perform additional processing
        """
        return NotImplementedError

    def pack_header(self):
        """
        Pack into string
        """
        try:
            values = [getattr(self, k.name) for k in self.__fields__]
            formats = copy.copy(self.__format__)
            for name in self.__blanks__:
                value = getattr(self, name)
                values.append(value)
                formats.append("{0}s".format(len(value)))
            formats = "{0}{1}".format(self.__byte_order__, "".join(formats))
            return str(struct.pack(formats, *values))
        except struct.error as error:
            logging.exception(error)

    def pack(self):
        packet_data = []
        for p in self.previous:
            packet_data.append(p.pack_header())
        packet_data.append(str(self.pack_header()))
        packet_data.append(str(self.data))
        return "".join(packet_data)

    @property
    def type(self):
        return self.__class__.__name__.lower()

    def __getattr__(self, k):
        try:
            return self.__getattribute__(k)
        except AttributeError:
            return None

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return "<{0} len: {1}>".format(self.__class__.__name__,
            self.__length__ + len(self.data))
