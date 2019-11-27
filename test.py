import socket
from struct import unpack

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 2055       # The port used by the server

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

while True:
	s.connect((HOST, PORT))
	data = s.recv(1024)
	version, count = unpack('!HH',data[0:4])
	print("We have " + str(count) + " packets and Version is:  " + str(version))