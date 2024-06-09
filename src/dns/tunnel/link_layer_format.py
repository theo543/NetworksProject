from ..packet import DNSPacket, DomainName

BASE36_CHARS = b"abcdefghijklmnopqrstuvwxyz0123456789"
BINARY_TO_BASE36_RATIO = 2

class LinkLayerMalformedData(Exception):
    pass

def byte_to_base36(byte: int) -> bytes:
    assert 0 <= byte < 256
    return bytes([BASE36_CHARS[byte // 36], BASE36_CHARS[byte % 36]])

def base36_to_byte(base36: bytes) -> int:
    assert len(base36) == 2
    try:
        return BASE36_CHARS.index(base36[0]) * 36 + BASE36_CHARS.index(base36[1])
    except ValueError as e:
        raise LinkLayerMalformedData(f"Invalid base36 character: {base36}") from e

def binary_to_base36(binary: bytes) -> bytes:
    b = bytearray()
    for byte in binary:
        b += byte_to_base36(byte)
    return bytes(b)

def base36_to_binary(base36: bytes) -> bytes:
    if len(base36) % 2 != 0:
        raise LinkLayerMalformedData("Base36 data length is not a multiple of 2")
    b = bytearray()
    for i in range(0, len(base36), 2):
        b.append(base36_to_byte(base36[i:i+2]))
    return bytes(b)

def bin_array_to_bin(bin_array: list[bytes]) -> bytes:
    b = bytearray()
    for bin in bin_array:
        b += len(bin).to_bytes(2, "big")
        b += bin
    return bytes(b)

def bin_to_bin_array(bin: bytes) -> list[bytes]:
    bin_array = []
    offset = 0
    try:
        while offset < len(bin):
            length = int.from_bytes(bin[offset:offset+2], "big")
            offset += 2
            bin_array.append(bin[offset:offset+length])
            offset += length
    except IndexError as e:
        raise LinkLayerMalformedData("Out of bounds while parsing binary array") from e
    return bin_array

def bin_array_to_base36(bin_array: list[bytes]) -> bytes:
    return binary_to_base36(bin_array_to_bin(bin_array))

def base36_to_bin_array(base36: bytes) -> list[bytes]:
    return bin_to_bin_array(base36_to_binary(base36))

def is_suffix(full: list[bytes], suffix: list[bytes]) -> bool:
    if len(suffix) + 1 != len(full):
        return False
    return suffix == full[1:]

def dns_answer_to_bin(packet: DNSPacket, tunnel_name: DomainName) -> bytes:
    """
    Used on the client-side to extract data from TXT records.
    """
    bin_answer = None
    for answer in packet.answers:
        if is_suffix(answer.name.labels, tunnel_name.labels):
            bin_answer = answer.data
            break
    if bin_answer is None:
        raise LinkLayerMalformedData("No answer matching tunnel name")
    bin_len = bin_answer[0]
    if bin_len + 1 != len(bin_answer):
        raise LinkLayerMalformedData("TXT entry length does not match data length - there must be a single string in the TXT entry")
    return bin_answer[1:]

def dns_query_to_bin(packet: DNSPacket, tunnel_name: DomainName) -> bytes:
    """
    Used on the server-side to extract data from a query.
    """
    bin_query = None
    for question in packet.questions:
        if is_suffix(question.name.labels, tunnel_name.labels):
            bin_query = question.name.labels[0]
            break
    if bin_query is None:
        raise LinkLayerMalformedData("No question matching tunnel name")
    return base36_to_binary(bin_query)
