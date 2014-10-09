#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import hashlib

sys.path.insert(1, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from cpkt import Packet, types, Field, Reader, Writer

from cpkt.protocols.ethernet import Ethernet, ETH_TYPE_IP, ETH_TYPE_IP6
from cpkt.protocols.ip import IP, IP6, IP_PROTO_TCP, IP_PROTO_UDP
from cpkt.protocols.tcp import TCP
from cpkt.protocols.udp import UDP

from cpkt.utils import md5sum

def ip_stack(packet):
    ethernet = Ethernet(packet)
    if ethernet.type == ETH_TYPE_IP:
        ip = IP(ethernet)
    elif ethernet.type == ETH_TYPE_IP6:
        ip = IP6(ethernet)
    else:
        return
    if ip.p == IP_PROTO_TCP:
        return TCP(ip)
    elif ip.p == IP_PROTO_UDP:
        return UDP(ip)
    else:
        return ip

def main():
    with Reader('http.pcap') as r:
        with Writer('test.pcap') as w:
            for ts, data in r:
                if not data:
                    continue
                packet = ip_stack(data)
                print(packet)
                w.write_packet(packet, packet_ts=ts)
    print("http.pcap {0}".format(md5sum('http.pcap')))
    print("test.pcap {0}".format(md5sum('test.pcap')))


if __name__ == '__main__':
    main()
