import socket
from dns.dns_format import DNSPacket, DNSResourceRecord, ResponseCode, dns_packet_from_bytes, dns_packet_to_bytes
import sys

def log_server(addr, port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind((addr, port))
    while True:
        data, addr = listener.recvfrom(1024)
        request = dns_packet_from_bytes(data)

        print(request)

        response_code = ResponseCode.NO_ERROR
        answers = []

        if len(request.questions) == 0:
            response_code = ResponseCode.FORMAT_ERROR
        elif len(request.questions) > 1:
            response_code = ResponseCode.NOT_IMPLEMENTED
        elif request.questions[0].qtype != 1:
            response_code = ResponseCode.NOT_IMPLEMENTED
        elif request.questions[0].qclass == 1:
            try:
                names = socket.gethostbyname_ex(str(request.questions[0].name))
                ipv4 = names[2][0]
                ipv4_bytes = socket.inet_aton(ipv4)
                answers = [
                    DNSResourceRecord(
                        name=request.questions[0].name,
                        type_=1,
                        class_=1,
                        ttl=60,
                        data=ipv4_bytes
                    )
                ]
            except socket.gaierror:
                response_code = ResponseCode.NAME_ERROR
        else:
            response_code = ResponseCode.NOT_IMPLEMENTED

        response = DNSPacket(
            request_id=request.request_id,
            is_response=True,
            authoritative_answer=False,
            truncation=False,
            recursion_desired=request.recursion_desired,
            reserved=0,
            recursion_available=True,
            response_code=response_code,
            questions=[],
            answers=answers,
            authorities=[],
            additional=[],
        )
        listener.sendto(dns_packet_to_bytes(response), addr)

def main():
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <addr> <port>')
        sys.exit(1)
    log_server(sys.argv[1], int(sys.argv[2]))

if __name__ == '__main__':
    main()
