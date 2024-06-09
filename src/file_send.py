from zlib import crc32
from dns.tunnel import init_stack
from dns.packet import DomainName
import sys
import logging
import threading
import time

def run():
    logging.basicConfig(level=logging.WARNING)
    src_ip = sys.argv[1]
    src_port = int(sys.argv[2])
    dest_ip = sys.argv[3]
    dest_port = int(sys.argv[4])
    domain_name = sys.argv[5]
    destination_virtual_port = int(sys.argv[6])
    transport = init_stack.init_dns_client_stack(src_ip, src_port, dest_ip, dest_port, DomainName.from_str(domain_name))
    sock = transport.connect_stream(destination_virtual_port)
    file = sys.argv[7]
    with open(file, "rb") as f:
        data = f.read()
    sock.push_data(len(file).to_bytes(8, "big"))
    sock.push_data(file.encode(encoding="utf-8"))
    for offset in range(0, len(data), 500):
        send = data[offset:offset+500]
        sock.push_data(bytes([0]))
        sock.push_data(len(send).to_bytes(2, "big"))
        sock.push_data(send)
        print(f"Bytes sent: {offset + len(send)}")
        checksum = sock.pop_data(4)
        expected_checksum = crc32(send).to_bytes(4, "big")
        print("Checksum:", checksum)
        print("Expected checksum:", expected_checksum)
    print("File sent")
    sock.push_data(bytes([1]))
    sock.close()

def main():
    logging.basicConfig(level=logging.INFO)
    th = threading.Thread(target=run)
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


if __name__ == "__main__":
    main()
