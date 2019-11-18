import socket
import sys
import binascii

host = ''
port = 2055

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.bind((host, port))
except socket.error as e:
    print(str(e))

s.listen(5)
while True:

    conn, addr = s.accept()
    data = conn.recvfrom(65565)
    packet = data[0]
    reply = 'Server output: '+ str(binascii.hexlify(data))
    print('packet: ' + str(packet))
    print(reply)
    print('connected to: ' +addr[0] + ':' + str(addr[1]))