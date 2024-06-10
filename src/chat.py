import logging
import sys
import threading
import time
from collections import deque

from dns.packet import DomainName
from dns.tunnel import init_stack

def read_input(input_buf):
    while True:
        try:
            data = sys.stdin.read(1)
            input_buf.append(data)
        except KeyboardInterrupt:
            sys.exit(0)

def run():
    input_buf: deque[str] = deque()
    th = threading.Thread(target=read_input, args=(input_buf,))
    th.daemon = True
    th.start()
    domain_name = sys.argv[1]
    virtual_port = int(sys.argv[2])
    active = sys.argv[3]
    src_ip = sys.argv[4]
    src_port = int(sys.argv[5])
    if active == "active":
        dst_ip = sys.argv[6]
        dst_port = int(sys.argv[7])
        transport = init_stack.init_dns_client_stack(src_ip, src_port, dst_ip, dst_port, DomainName.from_str(domain_name))
        sock = transport.connect_stream(virtual_port)
    elif active == "passive":
        transport = init_stack.init_dns_server_stack(src_ip, src_port, DomainName.from_str(domain_name))
        sock = transport.accept_stream_connection(virtual_port)
    else:
        raise ValueError("Invalid mode: " + active)
    while True:
        data = sock.pop_data(1, 0)
        if data:
            sys.stdout.write(data.decode(encoding='ascii'))
        if input_buf:
            sock.push_data(input_buf.popleft().encode(encoding='ascii'))

def main():
    logging.basicConfig(level=logging.INFO)
    th = threading.Thread(target=run)
    th.daemon = True
    th.start()
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    main()
