import time
import sys

from dns.tunnel.init_stack import init_dns_tunnel_stack_from_argv

def main():
    transport, args_read = init_dns_tunnel_stack_from_argv()
    virtual_port = int(sys.argv[args_read + 1])
    sock = transport.accept_stream_connection(virtual_port)
    bytes_received = 0
    start_time = time.time()
    try:
        while True:
            received_from_tunnel = sock.pop_data(999999999, 0)
            bytes_received += len(received_from_tunnel)
            elapsed_time = time.time() - start_time
            print(f"Received {bytes_received} bytes in {elapsed_time:.6f} seconds - average speed: {bytes_received/elapsed_time:.6f} bytes/s", end="\r")
            if len(received_from_tunnel) != 0:
                sock.push_data(bytes_received.to_bytes(8, "big"))
    except KeyboardInterrupt:
        print()

if __name__ == "__main__":
    main()
