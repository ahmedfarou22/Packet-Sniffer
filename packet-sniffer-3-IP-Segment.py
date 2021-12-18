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
            # print("       -->  Data : " + str(data))
            
            if proto == 1:
                (icmp_type, code, checksum,icmp_data) = icmp_packet(data)
                print('\n Layer 4 (ICMP Segment) ')
                print("     -->  ICMP type : " + str(icmp_type))
                print("     -->  ICMP Code : " + str(code))
                print("     -->  ICMP  Checksum : " + str(checksum))
                print("     -->  Rest Of   Data In the packet \n: " + str(icmp_data))
            
            if proto == 6:
                (src_port,dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_puh, flag_rst, flag_syn, flag_fin, dataaa) = tcp_segment(data)
                print('\n Layer 4 (TCP Segment)')
                print("     -->  Source Port : " + str(src_port))
                print("     -->  Destination Port: " + str(dest_port))
                print("     -->  Sequence : " + str(sequence))
                print("     -->  Acknowledgement : " + str(acknowledgement))
                print("     -->  flag urg : " + str(flag_urg))
                print("     -->  flag ack : " + str(flag_ack))
                print("     -->  flag puh : " + str(flag_puh))
                print("     -->  flag rst : " + str(flag_rst))
                print("     -->  flag syn : " + str(flag_syn))
                print("     -->  flag fin : " + str(flag_fin))
                print("     -->  Data : \n" + str(dataaa))
            
            if proto == 17:
                (udp_src_port, udp_dest_port, size, rest_data) = udp_segment(data)
                print('layer 4 (UDP Segment)')
                print("     -->  Source Port : " + str(udp_src_port))
                print("     -->  Destination Port: " + str(udp_dest_port))
                print("     -->  Size : " + str(size))
                print("     -->  Data : " + str(rest_data))
            

                
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


#unpack icmp 
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return icmp_type, code, checksum, data[4:]


# unpack tcp
def tcp_segment(data):
    (src_port,dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack("! H H L L H", data[:14])
    offset= (offset_reserved_flags >> 12 ) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_puh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port,dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_puh, flag_rst, flag_syn, flag_fin, data[offset:]

#unpakc UDP
def udp_segment(data):
    udp_src_port, udp_dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return udp_src_port, udp_dest_port, size, data[8:]




main()