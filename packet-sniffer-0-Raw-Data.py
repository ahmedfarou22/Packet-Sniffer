import socket 

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) #create a scoket object to 

while True:
        raww, addr =s.recvfrom(65536)
        print(raww)
