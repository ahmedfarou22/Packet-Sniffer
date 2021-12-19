import socket                                         
import time
import struct 

# create a socket object
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

# get local machine name
host = socket.gethostname()                           
port = 9999                                           

# bind to the port
serversocket.bind((host, port))                                  
serversocket.listen(5) # max 5                                

while True:
    # establish a connection
    clientsocket,addr = serversocket.accept()      

    print("Got a connection from %s" % str(addr))
    currentTime = time.ctime(time.time()) + "\r\n"
    clientsocket.send(currentTime.encode('ascii'))
    clientsocket.close()
    break


def main():
    while True:
        raww, addr =s.recvfrom(65536) 
        dest_mac , src_mac, prototype, raw_data = ethernet_head(raww) # layer 2 mac info
        ( versiion, header_length, time_to_live, proto,src,target, data) = ipv4_head(raw_data) # ip header layer 3 info
        (src_port,dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_puh, flag_rst, flag_syn, flag_fin, dataaa) = tcp_segment(data)
        
        if dest_port == 9999:
            print('\n Layer 2,3,4 Information ')
            print("     -->  Destination MAC : "+ str(dest_mac))
            print("     -->  Sorcue MAC : " + str(src_mac))
            print("     -->  Source IP : " + str(target))
            print("     -->  Destination IP: " + str(src))
            print("     -->  Source Port : " + str(src_port))
            print("     -->  Destination Port: " + str(dest_port))
            print("     -->  Protocol : "+ "TCP")
            break
        


            


                
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

main()