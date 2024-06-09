from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

class DNSException(Exception):
    pass

class DNSNotSupportedException(DNSException):
    pass

class DNSFormatException(DNSException):
    pass

def to_ne(data: int, size: int) -> bytes:
    assert has_bits(data, size * 8)
    return data.to_bytes(size, "big")

def from_ne(data: bytes) -> int:
    return int.from_bytes(data, "big")

def has_bits(value: int, bits: int) -> bool:
    return 0 <= value < (1 << bits)

@dataclass
class DNSPacket:
    request_id: int
    is_response: bool
    # STATUS and IQUERY not supported
    # opcode: int
    authoritative_answer: bool
    truncation: bool
    recursion_desired: bool
    reserved: int
    recursion_available: bool
    response_code: ResponseCode
    questions: list[DNSQuestion]
    answers: list[DNSResourceRecord]
    authorities: list[DNSResourceRecord]
    additional: list[DNSResourceRecord]

    def __post_init__(self):
        assert has_bits(self.request_id, 16)
        assert has_bits(self.reserved, 3)
        assert has_bits(len(self.questions), 16)
        assert has_bits(len(self.answers), 16)
        assert has_bits(len(self.authorities), 16)
        assert has_bits(len(self.additional), 16)

    def to_bytes(self) -> bytes:
        return dns_packet_to_bytes(self)

    @classmethod
    def from_bytes(cls, data: bytes) -> DNSPacket:
        return dns_packet_from_bytes(data)

class ResponseCode(Enum):
    NO_ERROR = 0
    FORMAT_ERROR = 1
    SERVER_FAILURE = 2
    NAME_ERROR = 3
    NOT_IMPLEMENTED = 4
    REFUSED = 5

@dataclass
class DNSQuestion:
    name: DomainName
    qtype: int
    qclass: int

    def __post_init__(self):
        assert has_bits(self.qtype, 16)

@dataclass
class DNSResourceRecord:
    name: DomainName
    type_: int
    class_: int
    ttl: int
    data: bytes

    def __post_init__(self):
        assert has_bits(self.type_, 16)
        assert has_bits(self.ttl, 32)
        assert has_bits(len(self.data), 16)

@dataclass
class DomainName:
    labels: list[bytes]

    @classmethod
    def from_str(cls, name: str) -> DomainName:
        labels = [label.encode("ascii") for label in name.split(".") if len(label) > 0]
        labels.append(b"")
        return cls(labels)

    def to_str(self) -> str:
        return str(self)

    @classmethod
    def from_bytes(cls, data: bytes) -> DomainName:
        offset, name = domain_name_from_bytes(data, 0)
        assert offset == len(data)
        return name

    def to_bytes(self) -> bytes:
        return domain_name_to_bytes(self)

    def __post_init__(self):
        assert len(self.labels) > 0
        assert self.labels[-1] == b"" # root domain
        for label in self.labels:
            assert has_bits(len(label), 6)

    def __str__(self):
        return ".".join(label.decode("ascii") for label in self.labels) # IDNs not supported

    def __repr__(self):
        return f"DomainName({self.labels})"

    def __eq__(self, other):
        if not isinstance(other, DomainName):
            return False

        if len(self.labels) != len(other.labels):
            return False

        for l1, l2 in zip(self.labels, other.labels):
            if l1.isascii() and l2.isascii():
                l1 = l1.lower()
                l2 = l2.lower()

            if l1 != l2:
                return False

        return True

def dns_packet_from_bytes(data: bytes) -> DNSPacket:
    try:
        request_id = from_ne(data[:2])
        flags = data[2:4]
        is_response = (flags[0] & 0b10000000) != 0
        if (flags[0] & 0b01111000) != 0:
            raise DNSNotSupportedException("Only QUERY (0) opcode is supported")
        authoritative_answer = (flags[0] & 0b00000100) != 0
        truncation = (flags[0] & 0b00000010) != 0
        recursion_desired = (flags[0] & 0b00000001) != 0
        recursion_available = (flags[1] & 0b10000000) != 0
        reserved = (flags[1] & 0b01110000) >> 4
        response_code = ResponseCode(flags[1] & 0b00001111)
        qdcount = from_ne(data[4:6])
        ancount = from_ne(data[6:8])
        nscount = from_ne(data[8:10])
        arcount = from_ne(data[10:12])

        offset = 12
        offset, questions = questions_from_bytes(data, offset, qdcount)
        offset, answers = resource_records_from_bytes(data, offset, ancount)
        offset, authorities = resource_records_from_bytes(data, offset, nscount)
        offset, additional = resource_records_from_bytes(data, offset, arcount)

        return DNSPacket(
            request_id=request_id,
            is_response=is_response,
            authoritative_answer=authoritative_answer,
            truncation=truncation,
            recursion_desired=recursion_desired,
            reserved=reserved,
            recursion_available=recursion_available,
            response_code=response_code,
            questions=questions,
            answers=answers,
            authorities=authorities,
            additional=additional,
        )
    except IndexError as exc:
        raise DNSFormatException() from exc

def questions_from_bytes(data: bytes, offset: int, count: int) -> tuple[int, list[DNSQuestion]]:
    questions: list[DNSQuestion] = []
    for _ in range(count):
        offset, name = domain_name_from_bytes(data, offset)
        qtype = from_ne(data[offset:offset + 2])
        qclass = from_ne(data[offset + 2:offset + 4])
        offset += 4
        questions.append(DNSQuestion(name, qtype, qclass))
    return offset, questions

def resource_records_from_bytes(data: bytes, offset: int, count: int) -> tuple[int, list[DNSResourceRecord]]:
    records: list[DNSResourceRecord] = []
    for _ in range(count):
        offset, name = domain_name_from_bytes(data, offset)
        type_ = from_ne(data[offset:offset + 2])
        class_ = from_ne(data[offset + 2:offset + 4])
        ttl = from_ne(data[offset + 4:offset + 8])
        data_len = from_ne(data[offset + 8:offset + 10])
        request_data = data[offset + 10:offset + 10 + data_len]
        offset += 10 + data_len
        records.append(DNSResourceRecord(name, type_, class_, ttl, request_data))
    return offset, records

def domain_name_from_bytes(data: bytes, offset: int) -> tuple[int, DomainName]:
    def get_ptr(offset_: int) -> int | None:
        if (data[offset_] & 0b11000000) == 0b11000000:
            return from_ne(data[offset_:offset_+2]) & 0b00111111
        return None

    if (ptr := get_ptr(offset)) is not None:
        _, name = domain_name_from_bytes(data, ptr)
        return offset + 2, name

    labels: list[bytes] = []
    while True:
        if (ptr := get_ptr(offset)) is not None:
            _, rest_of_name = domain_name_from_bytes(data, ptr)
            labels += rest_of_name.labels
            offset += 2
            break
        label_len = data[offset]
        offset += 1
        label = data[offset:offset+label_len]
        offset += label_len
        labels.append(label)
        if label_len == 0: # terminated by root domain
            break

    return offset, DomainName(labels)

def dns_packet_to_bytes(packet: DNSPacket) -> bytes:
    buf = bytearray()

    buf += to_ne(packet.request_id, 2)
    buf.append(
        0b10000000 * packet.is_response +
        0b00000100 * packet.authoritative_answer +
        0b00000010 * packet.truncation +
        0b00000001 * packet.recursion_desired
    )
    buf.append(
        0b10000000 * packet.recursion_available +
        (packet.reserved << 4) + # 0b01110000
        packet.response_code.value, # 0b00001111
    )
    buf += to_ne(len(packet.questions), 2)
    buf += to_ne(len(packet.answers), 2)
    buf += to_ne(len(packet.authorities), 2)
    buf += to_ne(len(packet.additional), 2)
    buf += questions_to_bytes(packet.questions)
    buf += resource_records_to_bytes(packet.answers)
    buf += resource_records_to_bytes(packet.authorities)
    buf += resource_records_to_bytes(packet.additional)

    if len(buf) > 512:
        buf[2] |= 0b00000010

    return bytes(buf)

def questions_to_bytes(questions: list[DNSQuestion]) -> bytes:
    buf = bytearray()

    for question in questions:
        buf += domain_name_to_bytes(question.name)
        buf += to_ne(question.qtype, 2)
        buf += to_ne(1, 2) # IN class

    return bytes(buf)

def resource_records_to_bytes(records: list[DNSResourceRecord]) -> bytes:
    buf = bytearray()

    for record in records:
        buf += domain_name_to_bytes(record.name)
        buf += to_ne(record.type_, 2)
        buf += to_ne(1, 2) # IN class
        buf += to_ne(record.ttl, 4)
        buf += to_ne(len(record.data), 2)
        buf += record.data

    return bytes(buf)

def domain_name_to_bytes(name: DomainName) -> bytes:
    buf = bytearray()

    for label in name.labels:
        buf.append(len(label))
        buf += label

    return bytes(buf)

def ascii_to_lowercase(label: bytes) -> bytes:
    msb = 0b10000000
    lowercase = 0b00100000
    def is_ascii(byte: int) -> bool:
        return (msb & byte) == 0
    return bytes([byte | (lowercase if is_ascii(byte) else 0) for byte in label])

def labels_eq(a: list[bytes], b: list[bytes]):
    for a_, b_ in zip(a, b):
        if ascii_to_lowercase(a_) != ascii_to_lowercase(b_):
            return False
    return True
