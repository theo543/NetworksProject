from dataclasses import dataclass
import socket
import sys

from dns.packet import DNSPacket, DNSResourceRecord, DomainName, ResponseCode, DNSException, DNSFormatException, DNSNotSupportedException

class InvalidConfigFile(Exception):
    pass

@dataclass
class DNSRecord:
    name: DomainName
    ttl: int
    record_type: int
    record_data: bytes

def parse_file(file_name: str) -> list[DNSRecord]:
    record_types = {
        "A": 1,
        "AAAA": 28,
        "CNAME": 5,
        "NS": 2,
        "TXT": 16,
    }
    records: list[DNSRecord] = []
    with open(file_name, encoding="ascii") as file:
        for line in file:
            tokens = line.split()
            if len(tokens) != 4:
                raise InvalidConfigFile(f"Invalid line: {line}")
            name = [part.encode(encoding="ascii") for part in tokens[0].split(".")]
            if name[-1] != b"":
                print(f"Domain name {tokens[0]} does not end with root domain - relative names not supported")
                sys.exit(1)
            try:
                ttl = int(tokens[1])
            except ValueError as e:
                raise InvalidConfigFile(f"Invalid TTL: {tokens[1]}") from e
            record_type = record_types.get(tokens[2], None)
            if record_type is None:
                raise InvalidConfigFile(f"Invalid record type: {tokens[2]}")
            record_data = tokens[3]
            if tokens[2] == "A":
                record_data = ipv4_str_to_bytes(record_data)
            elif tokens[2] == "AAAA":
                record_data = ipv6_str_to_bytes(record_data)
            elif tokens[2] == "TXT":
                record_data = record_data.encode(encoding="ascii")
                record_data = bytes([len(record_data)]) + record_data
            else:
                record_data = DomainName.from_str(record_data).to_bytes()
            records.append(DNSRecord(DomainName(name), ttl, record_type, record_data))
    return records

def ipv4_str_to_bytes(ipv4: str) -> bytes:
    def invalid(e: Exception | None = None):
        err = InvalidConfigFile(f"Invalid IPv4 address: {ipv4}")
        if e:
            raise err from e
        raise err

    parts = ipv4.split(".")
    if len(parts) != 4:
        invalid()
    b = bytearray()
    for part in parts:
        if len(part) not in (1, 2, 3) or not part.isdigit():
            invalid()
        try:
            b.append(int(part))
        except ValueError as e:
            invalid(e)
    return bytes(b)

def ipv6_str_to_bytes(ipv6: str) -> bytes:
    def invalid(e: Exception | None = None):
        err = InvalidConfigFile(f"Invalid IPv6 address: {ipv6}")
        if e:
            raise err from e
        raise err

    parts = ipv6.split(":")
    if len(parts) > 8 or len(parts) == 0:
        invalid()
    b = bytearray()
    missing_parts = 8 - len(parts)
    for part in parts:
        if len(part) == 0:
            if missing_parts == 0:
                invalid()
            b += bytes([0, 0] * (missing_parts + 1))
            missing_parts = 0
            continue
        try:
            b += int(part, 16).to_bytes(2, "big")
        except ValueError as e:
            invalid(e)
    if missing_parts > 0:
        invalid()
    return bytes(b)

def authoritative_dns(records: list[DNSRecord], addr: str, port: int):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind((addr, port))
    listener.settimeout(1)

    while True:
        try:
            request, (client_ip, client_port) = listener.recvfrom(1024)
        except socket.timeout:
            continue
        response: DNSPacket = DNSPacket(
            request_id=0,
            is_response=True,
            authoritative_answer=True,
            truncation=False,
            recursion_desired=False,
            reserved=0,
            recursion_available=False,
            response_code=ResponseCode.NAME_ERROR,
            questions=[],
            answers=[],
            authorities=[],
            additional=[],
        )
        try:
            request = DNSPacket.from_bytes(request)
            print(request)
            response.request_id = request.request_id
            response.recursion_desired = request.recursion_desired
            response.questions = request.questions
            if len(request.questions) != 1:
                raise DNSNotSupportedException()
            question = request.questions[0]
            for record in records:
                if (record.name == question.name) and (record.record_type in (question.qtype, 2, 255)):
                    response.response_code = ResponseCode.NO_ERROR
                    destination = response.answers if record.record_type != 2 else response.authorities
                    destination.append(DNSResourceRecord(
                        name=record.name,
                        type_=record.record_type,
                        class_=1,
                        ttl=record.ttl,
                        data=record.record_data
                    ))
            for answer in response.authorities:
                answer_ns = DomainName.from_bytes(answer.data)
                for record in records:
                    if record.name == answer_ns and record.record_type in (1, 28):
                        response.additional.append(DNSResourceRecord(
                            name=record.name,
                            type_=record.record_type,
                            class_=1,
                            ttl=record.ttl,
                            data=record.record_data
                        ))
        except DNSNotSupportedException:
            response.response_code = ResponseCode.NOT_IMPLEMENTED
        except DNSFormatException:
            response.response_code = ResponseCode.FORMAT_ERROR
        except DNSException:
            response.response_code = ResponseCode.SERVER_FAILURE
        listener.sendto(response.to_bytes(), (client_ip, client_port))

def main():
    if len(sys.argv) not in (3, 4):
        print(f'Usage: {sys.argv[0]} <records file> <addr> [<port>]')
        sys.exit(1)
    records = parse_file(sys.argv[1])
    authoritative_dns(records, sys.argv[2], int(sys.argv[3]) if len(sys.argv) == 4 else 53)

if __name__ == "__main__":
    main()
