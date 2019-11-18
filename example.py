import socket
import sys

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
    data = conn.recv(2048)
    reply = 'Server output: '+ binascii.hexlify(data)
    print(reply)
    print('connected to: ' +addr[0] + ':' + str(addr[1]))