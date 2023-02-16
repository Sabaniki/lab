#!/usr/bin/python3
import socket
import struct


def hex_str_to_int(hex_str: str, length: int) -> int:
    return int(hex_str[-length-1:], 16)

def rtt(hex_str: str):
    return hex_str_to_int(hex_str, 8)

def addr(hex_str: str):
    addr_long = hex_str_to_int(hex_str, 8)
    addr = socket.inet_ntoa(struct.pack(">L", addr_long))
    return addr

def port(hex_str: str):
    return hex_str_to_int(hex_str, 4)

COMMANDS = {
    "tmp_rtt"    : rtt ,
    "dbg_srcAddr": addr,
    "dbg_sport"  : port,
    "dbg_dstAddr": addr,
    "dbg_dport"  : port
}

while True:
    hex_str = input()
    if hex_str == "EOF": break
    for key, fn in COMMANDS.items():
        if key in hex_str:
            end = "\n" if key == "dbg_dport" else ","
            print(str(fn(hex_str)), end=end)
            break
