import sys
import threading
import time
import logging
import os

from dns.tunnel.init_stack import init_dns_client_stack, init_dns_server_stack
from dns.tunnel.ping_application import ping, server
from dns.packet import DomainName

def ping_t(transport, ping_port, client):
    if client:
        logging.info("Starting ping thread")
        ping(transport, ping_port)
    else:
        logging.info("Starting server thread")
        server(transport, ping_port)
    logging.info("Exiting thread")

def main():
    logging.basicConfig(level=logging.INFO if not os.getenv("LOGLEVEL") else os.getenv("LOGLEVEL"))
    local_stack_addr, local_stack_port, remote_stack_addr, remote_stack_port = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
    ping_port = int(sys.argv[5])
    domain_name = sys.argv[6]
    if remote_stack_addr == "server":
        transport = init_dns_server_stack(local_stack_addr, local_stack_port, DomainName.from_str(domain_name))
    else:
        transport = init_dns_client_stack(local_stack_addr, local_stack_port, remote_stack_addr, remote_stack_port, DomainName.from_str(domain_name))
    threads = []
    client = True if sys.argv[7] == "ping" else False if sys.argv[7] == "server" else None
    if client is None:
        raise ValueError("Invalid mode: " + sys.argv[7])
    for _ in range(10 if client else 1):
        logging.info("Creating thread - client = %s", client)
        th = threading.Thread(target=ping_t, args=(transport, ping_port, client))
        th.daemon = True
        th.start()
        threads.append(th)

    while True:
        try:
            time.sleep(1)
            if not any(th.is_alive() for th in threads):
                logging.info("All threads have exited")
                sys.exit(0)
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    main()
