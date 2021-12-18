import socket 
import struct 

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

def main():
    while True:
        raww, addr =s.recvfrom(65536)
        dest_mac , src_mac, prototype, raw_data = ethernet_head(raww)
        print('\n Layer 2 (Ethernet Frame) ')
        print("     -->  Destination MAC : "+ str(dest_mac))
        print("     -->  Sorcue MAC : " + str(src_mac))
        print("     -->  Protocol : " + str(prototype))
        
        if prototype == 8:
            ( versiion, header_length, time_to_live, proto,src,target, data) = ipv4_head(raw_data)
            print('\n Layer 3 (IP Packet Header) ')
            print("     -->  Version : " + str(versiion))
            print("     -->  Header length : " + str(header_length))
            print("     -->  Time to live : " + str(time_to_live))
            print("     -->  Protocal : " + str(proto))
            print("     -->  Source IP : " + str(target))
            print("     -->  Destination IP: " + str(src))
            print("       -->  Data : " + str(data))
            
            

                
# unpack and extract the data from ethernet fram layer 2
def ethernet_head(raw_data):
    dest_mac, src_mac, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    return get_mac_add(dest_mac), get_mac_add(src_mac), socket.htons(prototype), raw_data [14:]

def get_mac_add(raw):
    address = map('{:02x}'.format,raw)
    return ':'.join(address).upper()

# unpack and extract the ip v4 header information
def ipv4_head(data):
    versiion_header_length = data[0]
    versiion = versiion_header_length >> 4
    header_length = (versiion_header_length & 15) * 4
    time_to_live, proto, src, target = struct.unpack('! 8x b b 2x 4s 4s', data[:20])
    return versiion, header_length, time_to_live, proto, ip_format(src), ip_format(target), data[header_length:]

# format ip 
def ip_format(address):
    return '.'.join(map(str, address))



main()