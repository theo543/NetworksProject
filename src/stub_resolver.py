import socket
import sys
import time
import random

from dns.dns_format import DNSPacket, DNSQuestion, DomainName, ResponseCode, DNSException

RESOLVE_TIMEOUT = 5

def resolve_name(name: str, qtype: int, src_addr: str, server: str, port: int) -> DNSPacket | None:
    request = DNSPacket(
        request_id=random.randint(0, 65535),
        is_response=False,
        authoritative_answer=False,
        truncation=False,
        recursion_desired=True,
        reserved=0,
        recursion_available=False,
        response_code=ResponseCode.NO_ERROR,
        questions=[
            DNSQuestion(
                name=DomainName.from_str(name),
                qtype=qtype,
                qclass=1,
            )
        ],
        answers=[],
        authorities=[],
        additional=[],
    )
    print(request.questions)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind((src_addr, 0))
        listener.settimeout(1)
        listener.sendto(request.to_bytes(), (server, port))
        start_time = time.time()
        while start_time + RESOLVE_TIMEOUT > time.time():
            try:
                data, _ = listener.recvfrom(1024)
            except socket.timeout:
                continue
            try:
                response = DNSPacket.from_bytes(data)
            except DNSException:
                continue
            if response.request_id != request.request_id:
                continue
            return response
        return None

def log_server(src_ip, src_port, dns_server_ip, dns_server_port):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind((src_ip, src_port))
    listener.settimeout(1)
    while True:
        try:
            data, (dst_ip, dst_port) = listener.recvfrom(1024)
        except socket.timeout:
            continue

        request = DNSPacket.from_bytes(data)

        print(request)

        response = DNSPacket(
            request_id=request.request_id,
            is_response=True,
            authoritative_answer=False,
            truncation=False,
            recursion_desired=request.recursion_desired,
            reserved=0,
            recursion_available=True,
            response_code=ResponseCode.NO_ERROR,
            questions=[],
            answers=[],
            authorities=[],
            additional=[],
        )

        if len(request.questions) == 0:
            response.response_code = ResponseCode.FORMAT_ERROR
        elif len(request.questions) > 1:
            response.response_code = ResponseCode.NOT_IMPLEMENTED
        elif request.questions[0].qclass != 1:
            response.response_code = ResponseCode.NOT_IMPLEMENTED
        elif (qtype := request.questions[0].qtype) in [1, 28]:
            result = resolve_name(request.questions[0].name.to_str(), qtype, src_ip, dns_server_ip, dns_server_port)
            if result is None:
                print(f"Failed to resolve {request.questions[0].name.to_str()}")
                response.response_code = ResponseCode.NAME_ERROR
            else:
                response.authorities = result.authorities
                response.truncation = result.truncation
                response.recursion_available = result.recursion_available
                response.response_code = result.response_code
                response.questions = result.questions
                response.answers = result.answers
                response.authorities = result.authorities
                response.additional = result.additional
        else:
            response.response_code = ResponseCode.NOT_IMPLEMENTED

        listener.sendto(response.to_bytes(), (dst_ip, dst_port))

def main():
    if len(sys.argv) not in (4, 5):
        print(f'Usage: {sys.argv[0]} <addr> <port> <dns_server_ip> [<dns_server_port>]')
        sys.exit(1)
    log_server(sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4]) if len(sys.argv) == 5 else 53)

if __name__ == '__main__':
    main()
