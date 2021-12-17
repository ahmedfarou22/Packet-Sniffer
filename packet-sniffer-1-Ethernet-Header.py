import socket 
import struct 
import textwrap

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

def main():
    while True:
        raww, addr =s.recvfrom(65536)
        dest_mac , src_mac, prototype, raw_data = ethernet_head(raww)
        print('\n Ethernet Frame:')
        print("Destination MAC: "+ str(dest_mac) +" Sorcue MAC: " + str(src_mac) + " protocol: " + str(prototype) + " raw data: ")

def ethernet_head(raw_data):
    dest_mac, src_mac, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    return get_mac_add(dest_mac), get_mac_add(src_mac), socket.htons(prototype), raw_data [14:]

def get_mac_add(raw):
    address = map('{:02x}'.format,raw)
    return ':'.join(address).upper()






main()