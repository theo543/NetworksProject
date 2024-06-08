import socket
from .dns_format import DNSPacket, ResponseCode, dns_packet_from_bytes, dns_packet_to_bytes

def log_server(addr, port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind((addr, port))
    while True:
        data, addr = listener.recvfrom(1024)
        request = dns_packet_from_bytes(data)
        print(request)
        response = DNSPacket(
            request_id=request.request_id,
            is_response=True,
            authoritative_answer=False,
            truncation=False,
            recursion_desired=request.recursion_desired,
            reserved=0,
            recursion_available=False,
            response_code=ResponseCode.NOT_IMPLEMENTED,
            questions=[],
            answers=[],
            authorities=[],
            additional=[],
        )
        listener.sendto(dns_packet_to_bytes(response), addr)
