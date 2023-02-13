#!/usr/bin/python3

while True:
    hex_str = input()
    if hex_str == "EOF": break
    print(int(hex_str[-8:], 16))