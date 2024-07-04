import logging
import sys

from threading import Thread
import time
import socket

from dns.tunnel.init_stack import init_dns_tunnel_stack_from_argv
from dns.tunnel.transport_layer import StreamSocketInterface

class SOCKS5ConnectionError(Exception):
    error_code: int
    def __init__(self, error_code: int):
        self.error_code = error_code

def conn_handler(sock: StreamSocketInterface):
    addr_type = sock.pop_data(1)
    addr_len = int.from_bytes(sock.pop_data(1), "big")
    addr = sock.pop_data(addr_len)
    match addr_type:
        case b"\x01":
            addr_decoded = socket.inet_ntop(socket.AF_INET, addr)
        case b"\x04":
            addr_decoded = socket.inet_ntop(socket.AF_INET6, addr)
        case b"\x03":
            addr_decoded = socket.gethostbyname(addr.decode())
        case _:
            raise SOCKS5ConnectionError(0x08) # Address type not supported
    port = int.from_bytes(sock.pop_data(2), "big")
    logging.info("Received request to connect to %s:%d", addr_decoded, port)
    try:
        internet_sock = socket.create_connection((addr_decoded, port))
    except socket.timeout as e:
        raise SOCKS5ConnectionError(0x04) from e # Host unreachable
    except ConnectionRefusedError as e:
        raise SOCKS5ConnectionError(0x05) from e # Connection refused
    except OSError as e:
        raise SOCKS5ConnectionError(0x01) from e # General error
    sock_name = internet_sock.getsockname()
    bind_addr, bind_port = sock_name[0], sock_name[1]
    logging.info("Connected to %s:%d", addr_decoded, port)
    sock.push_data(b"\x00")
    if ":" in bind_addr:
        sock.push_data(b"\x04")
        to_send_addr = socket.inet_pton(socket.AF_INET6, bind_addr)
    else:
        sock.push_data(b"\x01")
        to_send_addr = socket.inet_pton(socket.AF_INET, bind_addr)
    sock.push_data(len(to_send_addr).to_bytes(1, "big"))
    sock.push_data(to_send_addr)
    sock.push_data(bind_port.to_bytes(2, "big"))
    internet_sock.settimeout(0.05)
    while True:
        received_from_tunnel = sock.pop_data(1024, 0)
        try:
            received_from_internet = internet_sock.recv(1024)
        except socket.timeout:
            received_from_internet = b""
        if not received_from_tunnel and not received_from_internet:
            time.sleep(0.1)
            continue
        if received_from_tunnel:
            internet_sock.sendall(received_from_tunnel)
        if received_from_internet:
            sock.push_data(received_from_internet)

def accept():
    transport, args_read = init_dns_tunnel_stack_from_argv()
    virtual_port = int(sys.argv[args_read + 1])
    while True:
        sock: StreamSocketInterface = transport.accept_stream_connection(virtual_port)
        t = Thread(target=conn_handler, args=(sock,))
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
