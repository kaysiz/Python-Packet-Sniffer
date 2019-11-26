import socket, struct

from socket import inet_ntoa

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('127.0.0.1', 2055))

while True:
	buf, addr = sock.recvfrom(1500)

	(version, count) = struct.unpack('!HH',buf[0:4])
	print(str(version))