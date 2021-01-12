#!/usr/bin/env python3
# https://github.com/EONRaider/Packet-Sniffer

__author__ = 'EONRaider @ keybase.io/eonraider'

import abc
import argparse
import time
from itertools import count
from socket import ntohs, socket, PF_PACKET, SOCK_RAW
from twilio.rest import Client ##header buat twilio ke whatsapp (6)

import protocols

i = ' ' * 4  # Basic indentation level
intruderIPGlobal = [] ## fungsi untuk menambahkan variabel untuk menyimpan IP intruder (1)


class PacketSniffer(object):
    def __init__(self, interface: str):
        self.interface = interface
        self.data = None
        self.protocol_queue = ['Ethernet']
        self.__observers = list()

    def register(self, observer):
        self.__observers.append(observer)

    def __notify_all(self, *args):
        for observer in self.__observers:
            observer.update(*args)
        del self.protocol_queue[1:]

    def execute(self):
        with socket(PF_PACKET, SOCK_RAW, ntohs(0x0003)) as sock:
            if self.interface is not None:
                sock.bind((self.interface, 0))
            for self.packet_num in count(1):
                raw_packet = sock.recv(2048)
                start: int = 0
                for proto in self.protocol_queue:
                    proto_class = getattr(protocols, proto)
                    end: int = start + proto_class.header_len
                    protocol = proto_class(raw_packet[start:end])
                    setattr(self, proto.lower(), protocol)
                    if protocol.encapsulated_proto is None:
                        break
                    self.protocol_queue.append(protocol.encapsulated_proto)
                    start = end
                self.data = raw_packet[end:]
                self.__notify_all(self)


class OutputMethod(abc.ABC):
    """Interface for the implementation of all classes responsible for
    further processing and/or output of the information gathered by
    the PacketSniffer class (referenced as 'subject')."""

    def __init__(self, subject):
        subject.register(self)

    @abc.abstractmethod
    def update(self, *args, **kwargs):
        pass

class SniffToScreen(OutputMethod):
    def __init__(self, subject, *, displaydata: bool):
        super().__init__(subject)
        self.p = None
        self.display_data = displaydata

    def update(self, packet):
        self.p = packet
        #self._display_output_header()
        self._display_packet_info()
        #self._display_packet_contents()

    def _display_output_header(self):
        local_time = time.strftime('%H:%M:%S', time.localtime())
        print('[>] Packet #{0} at {1}:'.format(self.p.packet_num, local_time))

    def _display_packet_info(self): ## menambahkan logika pada fungsi ini. jadi disini dideclare IP mana aja yg kedeteksi dan pengecualiannya (2)
        printTCP = False
        intruderIP = intruderIPGlobal
        lastIP = ""
        for proto in self.p.protocol_queue:
            if proto.lower() == "ipv4":
                if self.p.ipv4.source != "103.41.206.73" and self.p.ipv4.source != "123.253.235.74": #(3)
                    if self.p.ipv4.source in intruderIP:
                        intruderIP = False
                    else:
                        intruderIP.append(self.p.ipv4.source)
                        self._display_output_header()
                        getattr(self, '_display_{}_data'.format(proto.lower()))()
                        lastIP = self.p.ipv4.source
                        printTCP = True
                else:
                    printTCP = False
            if proto.lower() == "tcp" and printTCP == True:
                account_sid = 'ACb92fe50de727531b2ba92945670f0e86' ## ini token token buat nyambungin twilio ke whatsapp kita (7)
                auth_token = '3edc21dfcfede199ec0a22477a3bcb08'
                client = Client(account_sid, auth_token)
                message = client.messages.create(
                              from_='whatsapp:+14155238886',
                              body='Ada intruder dengan IP : ' + lastIP,
                              to='whatsapp:+6281333220297'
                          )
                print(message.sid)
                getattr(self, '_display_{}_data'.format(proto.lower()))()


    def _display_ethernet_data(self):
        print('{0}[+] MAC {1:.>23} -> {2}'.format(i, self.p.ethernet.source,
                                                  self.p.ethernet.dest))

    def _display_ipv4_data(self):
        print('{0}[+] IPv4 {1:.>22} -> {2: <15} | '
              'PROTO: {3} TTL: {4}'.format(i, self.p.ipv4.source,
                                           self.p.ipv4.dest,
                                           self.p.ipv4.encapsulated_proto,
                                           self.p.ipv4.ttl))

    def _display_ipv6_data(self):
        print('{0}[+] IPv6 {1:.>22} -> {2: <15}'.format(i, self.p.ipv6.source,
                                                        self.p.ipv6.dest))

    def _display_arp_data(self):
        if self.p.arp.oper == 1:  # ARP Request
            print('{0}[+] ARP Who has {1: >13} ? '
                  '-> Tell {2}'.format(i, self.p.arp.target_proto,
                                       self.p.arp.source_proto))
        else:                     # ARP Reply
            print('{0}[+] ARP {1:.>23} -> '
                  'Is at {2}'.format(i, self.p.arp.source_proto,
                                     self.p.arp.source_hdwr))

    def _display_tcp_data(self):
        print('{0}[+] TCP {1:.>23} -> {2: <15} | '
              'Flags: {3} > {4}'.format(i, self.p.tcp.sport,
                                        self.p.tcp.dport,
                                        self.p.tcp.flag_hex,
                                        self.p.tcp.flag_txt))

    def _display_udp_data(self):
        print('{0}[+] UDP {1:.>23} -> {2}'.format(i, self.p.udp.sport,
                                                  self.p.udp.dport))

    def _display_icmp_data(self):
        print('{0}[+] ICMP {1:.>22} -> {2: <15} | '
              'Type: {3}'.format(i, self.p.ipv4.source,
                                 self.p.ipv4.dest,
                                 self.p.icmp.type_txt))

    def _display_packet_contents(self): # (4)
        if self.display_data is True:
            print('{0}[+] DATA:'.format(i))
            data = self.p.data.decode(errors='ignore').\
                replace('\n', '\n{0}'.format(i*2))
            print('{0}{1}'.format(i, data))


def sniff(interface: str, displaydata: bool):
    """Control the flow of execution of the Packet Sniffer tool."""

    packet_sniffer = PacketSniffer(interface)
    to_screen = SniffToScreen(subject=packet_sniffer,
                              displaydata=displaydata)
    try:
        print('\n[>>>] Sniffer initialized. Waiting for incoming packets. '
              'Press Ctrl-C to abort...\n')
        packet_sniffer.execute()
    except KeyboardInterrupt:
        print("")
        print("IP yang mengintrusi:") ## menampilkan list IP yg dianggap intruder (5) 
        for x in intruderIPGlobal:
            print(x)
        raise SystemExit('Aborting packet capture...')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A pure-Python network packet '
                                                 'sniffer.')
    parser.add_argument('-i', '--interface', type=str, default=None,
                        help='Interface from which packets will be captured '
                             '(captures from all available interfaces by '
                             'default).')
    parser.add_argument('-d', '--displaydata', action='store_true',
                        help='Output packet data during capture.')
    cli_args = parser.parse_args()
    sniff(interface=cli_args.interface,
          displaydata=cli_args.displaydata)
