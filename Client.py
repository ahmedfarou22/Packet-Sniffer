import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create a socket object

host = socket.gethostname()                           
port = 9999 

s.connect((host, port))      # connection to hostname on the port.
tm = s.recv(1024)     # Receive no more than 1024 bytes                                

s.close()
print("The time got from the server is %s" % tm.decode('ascii'))