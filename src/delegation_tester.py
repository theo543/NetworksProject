import socket
import sys
import threading
import time

from dns.packet import DNSPacket, ResponseCode, DNSResourceRecord, DomainName

def listen_dns(listen_host: str, listen_port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((listen_host, listen_port))
        listener.listen(1)
        while True:
            conn, addr = listener.accept()
            with conn:
                size = conn.recv(2)
                size = int.from_bytes(size, "big")
                data = conn.recv(1024)
                if len(data) < size:
                    conn.sendall(b"ERROR: Incomplete data")
                    continue
                if not data:
                    break
                packet = DNSPacket.from_bytes(data)
                print(f"Received packet from {addr[0]}:{addr[1]}: {packet}")
                txt = b"Hello World!"
                response = DNSPacket(
                    request_id=packet.request_id,
                    is_response=True,
                    authoritative_answer=False,
                    truncation=False,
                    recursion_desired=packet.recursion_desired,
                    reserved=0,
                    recursion_available=False,
                    response_code=ResponseCode.NOT_IMPLEMENTED,
                    questions=[],
                    answers=[],
                    authorities=[],
                    additional=[DNSResourceRecord(
                        name = DomainName.from_str("delegation.tester.localhost"),
                        ttl = 0,
                        class_ = 1,
                        type_ = 16,
                        data = len(txt).to_bytes(1) + txt
                    )]
                )
                conn.sendall(response.to_bytes())

def main():
    host, port = sys.argv[1], int(sys.argv[2])
    listen_thread = threading.Thread(target=listen_dns, args=(host, port))
    listen_thread.daemon = True
    listen_thread.start()
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            sys.exit(0)

if __name__ == "__main__":
    main()
