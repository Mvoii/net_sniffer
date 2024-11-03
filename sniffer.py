#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import struct
import sys

parser = argparse.ArgumentParser(description="Network Packet Sniffer")
parser.add_argument("--ip", help="IP address to sniff on", required=True)
parser.add_argument("--protocal", help="Protocal to sniff (TCP/ICMP)", required=True)
parser.add_argument("--data", help="Display data", action="store_true")
opts = parser.parse_args()


class Packet:
    def __init__(self, data):
        self.packet = data
        header = struct.unpack("<BBHHHBBH4s4s", self.packet[0:20])
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.off = header[4]
        self.ttl = header[5]
        self.pro = header[6]
        self.num = header[7]
        self.src = header[8]
        self.dst = header[9]

        self.src_addr = ipaddress.ip_address(self.src)
        self.dst_addr = ipaddress.ip_address(self.dst)

        self.protocal_map = {1: "ICMP", 6: "TCP"}

        try:
            self.protocal = self.protocal_map[self.pro]
        except Exception as e:
            print(f"{e} N")
            self.protocal = str(self.pro)

    def print_header_short(self):
        print(f"Protocal: {self.protocal} {self.src_addr} -> {self.dst_addr}")

    def print_data(self):
        data = self.packet[20:]
        print("*" * 10 + "ASCII START" + "*" * 10)

        for b in data:
            if b < 128:
                print(chr(b), end=" ")
            else:
                print(chr(b), end=" ")

        print("*" * 10 + "ASCII END" + "*" * 10)


def sniff(host):
    if opts.proto == "tcp":
        socket_protocal = socket.IPPROTO_TCP
    else:
        socket_protocal = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocal)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_ICMP, socket.IP_HDRINCL, 1)

    try:
        while True:
            raw_data = sniffer.recv(65556)
            packet = Packet(raw_data)
            packet.print_header_short()
            if opts.data:
                packet.print_data()
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    sniff(opts.ip)
