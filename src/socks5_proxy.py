from threading import Thread
import socket
import time
import sys

from dns.tunnel.init_stack import init_dns_tunnel_stack_from_argv
from dns.tunnel.transport_layer import TransportLayerInterface

def conn_handler(transport: TransportLayerInterface, virtual_port: int, conn: socket.socket):
    ver = conn.recv(1)
    if ver != b"\x05":
        conn.sendall(b"\x05\xFF") # VER = 5, METHOD = No acceptable methods
        conn.close()
        return
    methods = conn.recv(1)
    conn.recv(int.from_bytes(methods, "big")) # don't care
    conn.sendall(b"\x05\x00") # VER = 5, METHOD = No authentication required
    ver = conn.recv(1)
    cmd = conn.recv(1)
    rsv = conn.recv(1)
    if cmd != b"\x01" or rsv != b"\x00":
        conn.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
        # VER = 1, REP = Command not supported, RSV = 0, ATYP = IPv4, ADDR = 0, PORT = 0
        conn.close()
        return
    atyp = conn.recv(1)
    match atyp:
        case b"\x01":
            addr = conn.recv(4)
        case b"\x04":
            addr = conn.recv(16)
        case b"\x03":
            domain_len = conn.recv(1)
            addr = conn.recv(int.from_bytes(domain_len, "big"))
        case _:
            conn.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            # VER = 1, REP = Address type not supported, RSV = 0, ATYP = IPv4, ADDR = 0, PORT = 0
            conn.close()
            return
    dst_port = conn.recv(2)

    relay_sock = transport.connect_stream(virtual_port)
    relay_sock.push_data(atyp + len(addr).to_bytes(1) + addr + dst_port)
    response = relay_sock.pop_data(1)
    bind_addr_type = relay_sock.pop_data(1)
    bind_addr_len = int.from_bytes(relay_sock.pop_data(1))
    bind_addr = relay_sock.pop_data(bind_addr_len)
    bind_port = relay_sock.pop_data(2)
    conn.sendall(b"\x05" + response + b"\x00" + bind_addr_type + bind_addr + bind_port)
    if response != b"\x00":
        conn.close()
        return
    while True:
        received_from_tunnel = relay_sock.pop_data(1024, 0)
        received_from_internet = conn.recv(1024)
        if not received_from_tunnel and not received_from_internet:
            time.sleep(0.1)
            continue
        if received_from_tunnel:
            conn.sendall(received_from_tunnel)
        if received_from_internet:
            relay_sock.push_data(received_from_internet)

def accept():
    transport, args_read = init_dns_tunnel_stack_from_argv()
    virtual_port = int(sys.argv[args_read])
    listen_interface = sys.argv[args_read + 1]
    listen_port = int(sys.argv[args_read + 2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((listen_interface, listen_port))
    sock.listen(5)
    while True:
        conns = sock.accept()
        for conn in conns:
            t = Thread(target=conn_handler, args=(transport, virtual_port, conn))
            t.daemon = True
            t.start()

def main():
    t = Thread(target=accept)
    t.daemon = True
    t.start()
    while t.is_alive():
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    main()
