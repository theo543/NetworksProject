import sys
import threading
import time
import logging

from dns.tunnel.dummy_stack import init_dummy_stack
from dns.tunnel.ping_application import ping, server

def ping_t(transport, ping_port, client):
    if client:
        logging.info("Starting ping thread")
        ping(transport, ping_port)
    else:
        logging.info("Starting server thread")
        server(transport, ping_port)
    logging.info("Exiting thread")

def main():
    logging.basicConfig(level=logging.DEBUG)
    local_stack_addr, local_stack_port, remote_stack_addr, remote_stack_port = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
    ping_port = int(sys.argv[5])
    transport = init_dummy_stack(local_stack_addr, local_stack_port, remote_stack_addr, remote_stack_port)
    threads = []
    client = True if sys.argv[6] == "ping" else False if sys.argv[6] == "server" else None
    if client is None:
        raise ValueError("Invalid mode")
    for _ in range(10 if client else 1):
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
