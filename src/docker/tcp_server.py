# TCP Server
import socket
import time

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)

port = 10000
adresa = '0.0.0.0'

server_address = (adresa, port)
sock.bind(server_address)

sock.listen(1)

print("Wait for connection...")
conn, address = sock.accept()
print(f"Connection from {address}")

sock.close()

while True:
    time.sleep(3)
    data = conn.recv(1024)
    print(f"Received: {data}")
    conn.send(b"Received: " + data)
