import sys
import random

from dns.tunnel.init_stack import init_dns_tunnel_stack_from_argv

def main():
    transport, args_read = init_dns_tunnel_stack_from_argv()
    virtual_port = int(sys.argv[args_read + 1])
    sock = transport.connect_stream(virtual_port)
    print("Sending garbage data to the server...")
    data_sent = 0
    data_server_received = 0
    while True:
        if data_sent - data_server_received < 1024:
            data = bytes([random.randint(0, 255) for _ in range(100)])
            data_sent += len(data)
            sock.push_data(data)
        while True:
            update = sock.pop_data(8, 0)
            if len(update) == 0:
                break
            if len(update) != 8:
                update += sock.pop_data(8 - len(update))
            data_server_received = int.from_bytes(update, "big")
        print(f"Sent {data_sent} bytes - server received {data_server_received} bytes", end="\r")

if __name__ == "__main__":
    main()
