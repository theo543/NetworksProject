import sys
import threading
import time
import logging

from dns.tunnel.dummy_stack import init_dummy_stack
from dns.tunnel.ping_application import ping, server

def thread():
    local_stack_addr, local_stack_port, remote_stack_addr, remote_stack_port = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
    ping_port = int(sys.argv[5])
    transport = init_dummy_stack(local_stack_addr, local_stack_port, remote_stack_addr, remote_stack_port)
    if sys.argv[6] == "ping":
        ping(transport, ping_port)
    elif sys.argv[6] == "server":
        server(transport, ping_port)
    else:
        print("Invalid mode")
    logging.info("Exiting thread")

def main():
    logging.basicConfig(level=logging.DEBUG)
    th = threading.Thread(target=thread)
    th.daemon = True
    th.start()
    while True:
        try:
            time.sleep(1)
            if not th.is_alive():
                sys.exit(0)
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    main()
