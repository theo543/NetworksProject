# TCP client
import socket
import time

port = 10000
adresa = '198.7.0.2'
server_address = (adresa, port)
msg = "Hello, World!"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
sock.connect(server_address)

while True:
    time.sleep(3)
    sock.send(msg.encode('utf-8'))
    data = sock.recv(1024)
    print(f'Content primit: "{data}"')
