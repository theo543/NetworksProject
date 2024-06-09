import logging
import time
from zlib import crc32
from dns.tunnel import init_stack
from dns.packet import DomainName
import sys
import threading
from pathlib import Path

def run():
    logging.basicConfig(level=logging.WARNING)
    src_ip = sys.argv[1]
    src_port = int(sys.argv[2])
    domain_name = sys.argv[3]
    source_virtual_port = int(sys.argv[4])
    transport = init_stack.init_dns_server_stack(src_ip, src_port, DomainName.from_str(domain_name))
    sock = transport.accept_stream_connection(source_virtual_port)
    name_length = int.from_bytes(sock.pop_data(8), "big")
    name = sock.pop_data(name_length).decode(encoding="utf-8")
    print("File name:", name)
    safe_name = Path(Path(name).name)
    print("Saving to path:", safe_name.resolve())
    with open(safe_name, "wb") as f:
        while True:
            is_end = int.from_bytes(sock.pop_data(1), "big")
            if is_end:
                print("End of file")
                break
            length = int.from_bytes(sock.pop_data(2), "big")
            print(f"Will receive {length} bytes")
            data = sock.pop_data(length)
            f.write(data)
            f.flush()
            checksum = crc32(data).to_bytes(4, "big")
            print("Checksum:", checksum)
            sock.push_data(checksum)
        print(f"Bytes received: {f.tell()}")
    print("File received")
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
