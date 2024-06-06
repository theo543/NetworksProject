import socket
import os
import sys
import signal
import time
from ipaddress import IPv4Address
from dataclasses import dataclass
import logging

import requests

USER_AGENT = "UDP Traceroute Homework for Networks course at University of Bucharest (https://networks.hypha.ro/)"
USER_AGENT_B = USER_AGENT.encode("ascii")

# cSpell: ignoreRegExp socket.\w+

def ones_complement_sum(a, b):
    # RFC 1071:
    # On a 2's complement machine, the 1's complement sum must be
    # computed by means of an "end around carry", i.e., any overflows
    # from the most significant bits are added into the least
    # significant bits. See the examples below
    c = a + b
    c_without_overflows = c & 0xffff
    c_overflows_shifted = c >> 16
    return c_without_overflows + c_overflows_shifted

def check_internet_checksum(data: bytes) -> bool:
    # RFC 1071:
    # Adjacent octets to be checksummed are paired to form 16-bit
    # integers, and the 1's complement sum of these 16-bit integers is
    # formed.
    checksum = 0
    for i in range(1, len(data), 2):
        checksum = ones_complement_sum(checksum, int.from_bytes(data[i-1:i+1], "big"))
    if len(data) % 2 == 1:
        padded_last_byte = data[-1:] + bytes([0])
        checksum = ones_complement_sum(checksum, int.from_bytes(padded_last_byte, "big"))
    # RFC 1071:
    # To check a checksum, the 1's complement sum is computed over the
    # same set of octets, including the checksum field.  If the result
    # is all 1 bits (-0 in 1's complement arithmetic), the check
    # succeeds.
    return checksum == 0xffff

def get_ip_info(ip: IPv4Address, timeout: int) -> str:
    if ip.is_private:
        return "No IP info available: private range"

    header = {"user-agent": USER_AGENT}
    query_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,lat,lon"

    def error(msg: str) -> str:
        logging.error("%s, query URL: %s, timeout: %d", msg, query_url, timeout)
        return msg

    try:
        response = requests.get(query_url, headers=header, timeout=timeout)
    except requests.exceptions.RequestException as e:
        return error(f"No IP info available: Got exception {e.__class__.__name__} when sending request to API, exception message: {e}")

    if response.status_code != 200:
        return error(f"No IP info available: Got status code {response.status_code} from API")

    try:
        ip_info = response.json()
    except requests.exceptions.JSONDecodeError:
        return error("No IP info available: Could not decode JSON response from API")

    assert isinstance(ip_info, dict)
    if ip_info["status"] != "success":
        return error(f"No IP info available: {ip_info['message']}")

    def get(key: str, name: str) -> str:
        value = ip_info.get(key, None)
        if value is None:
            return f"Unknown {name}"
        return f"{name}: \"{value}\""
    country = get("country", "Country")
    region = get("regionName", "Region")
    city = get("city", "City")
    isp = get("isp", "ISP")
    org = get("org", "Organization")
    as_ = get("as", "Autonomous System")
    lat = ip_info.get("lat", "Lat")
    lon = ip_info.get("lon", "Lon")

    result = f"{country}, {region}, {city}, {lat}, {lon}, {isp}, {org}, {as_}"

    reverse_dns = socket.getfqdn(str(ip))
    if reverse_dns != str(ip):
        result += f", Reverse DNS: {reverse_dns}"

    return result

class UDPSendError(Exception):
    pass

@dataclass
class TraceRouteResult:
    ip: IPv4Address
    icmp_type: int
    icmp_code: int

def traceroute(ip: IPv4Address, destination_port: int, ttl: int, timeout: int, udp_send_sock: socket.socket, icmp_recv_socket: socket.socket) -> TraceRouteResult | None:
    udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    source_port = udp_send_sock.getsockname()[1] # socket name is (ip, port)

    content = USER_AGENT_B
    bytes_sent = udp_send_sock.sendto(content, (str(ip), destination_port))
    if bytes_sent != len(content):
        raise UDPSendError(f"Could not send all {len(content)} bytes to {ip}:{destination_port}")
    sent_udp_length = bytes_sent + 8 # UDP header is 8 bytes

    start_time = time.time()
    while (time.time() - start_time) < timeout:
        icmp_recv_socket.settimeout(timeout - (time.time() - start_time))
        try:
            data, (addr, _port) = icmp_recv_socket.recvfrom(63535)
        except TimeoutError:
            break

        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = version_ihl & (0b1111)

        if not (version == 4 and ihl >= 5):
            logging.debug("Ignoring non-IPv4 packet")
            continue

        icmp_packet = data[ihl * 4:]
        if not check_internet_checksum(icmp_packet):
            logging.warning("Invalid ICMP checksum, discarding packet")
            continue

        icmp_header = icmp_packet[0:8]
        icmp_data = icmp_packet[8:]
        icmp_type = icmp_header[0]
        icmp_code = icmp_header[1]

        if not ((icmp_type == 11 and icmp_code == 0) or icmp_type == 3):
            logging.debug("Ignoring irrelevant ICMP packet (not Time Exceeded or Destination Unreachable)")
            continue

        embedded_ihl_version = icmp_data[0]
        embedded_version = embedded_ihl_version >> 4
        embedded_ihl = embedded_ihl_version & (0b1111)
        embedded_protocol = icmp_data[9]

        if not (embedded_version == 4 and embedded_ihl >= 5 and embedded_protocol == socket.IPPROTO_UDP):
            logging.debug("Ignoring irrelevant embedded packet (not IPv4 or not UDP)")
            continue

        embedded_udp_packet = icmp_data[embedded_ihl * 4:]
        embedded_udp_header = embedded_udp_packet[0:8]
        embedded_udp_data = embedded_udp_packet[8:]
        embedded_udp_source_port = int.from_bytes(embedded_udp_header[0:2], "big")
        embedded_udp_destination_port = int.from_bytes(embedded_udp_header[2:4], "big")
        embedded_udp_length = int.from_bytes(embedded_udp_header[4:6], "big")

        # Checking the UDP checksum doesn't work, since NAT changes the source address and that goes into the checksum
        # embedded_udp_checksum = int.from_bytes(embedded_udp_header[6:8], "big")
        # udp_pseudo_header = icmp_data[12:20] + bytes([0, socket.IPPROTO_UDP]) + int.to_bytes(sent_udp_length, 2, "big")
        # if not (embedded_udp_checksum == 0 or check_internet_checksum(udp_pseudo_header + embedded_udp_header + embedded_udp_data)):
        #     print("Invalid UDP checksum in packet embedded in ICMP packet, discarding packet", file=sys.stderr)
        #     continue

        if not (embedded_udp_source_port == source_port and embedded_udp_destination_port == destination_port):
            logging.debug("Ignoring irrelevant embedded UDP packet (source port or destination port mismatch, not for this traceroute)")
            continue

        if embedded_udp_length != sent_udp_length:
            logging.warning("Ignoring embedded UDP packet despite matching ports, length mismatch")

        if not USER_AGENT_B.startswith(embedded_udp_data):
            logging.warning("Ignoring embedded UDP packet despite matching ports, data mismatch")

        return TraceRouteResult(ip=IPv4Address(addr), icmp_type=icmp_type, icmp_code=icmp_code)

    return None

ICMP_HUMAN_READABLE_NAMES : dict[tuple[int, int], str] = {
    (3, 0): "Net Unreachable",
    (3, 1): "Host Unreachable",
    (3, 2): "Protocol Unreachable",
    (3, 3): "Port Unreachable",
    (3, 4): "Fragmentation Needed and Don't Fragment was Set",
    (3, 5): "Source Route Failed",
    (3, 6): "Destination Network Unknown",
    (3, 7): "Destination Host Unknown",
    (3, 8): "Source Host Isolated",
    (3, 9): "Destination Network Administratively Prohibited",
    (3, 10): "Destination Host Administratively Prohibited",
    (3, 11): "Destination Network Unreachable for Type of Service",
    (3, 12): "Destination Host Unreachable for Type of Service",
    (3, 13): "Communication Administratively Prohibited",
    (3, 14): "Host Precedence Violation",
    (3, 15): "Precedence cutoff in effect",
}

def main():
    signal.signal(signal.SIGINT, lambda _signal, _frame: sys.exit(1)) # exit on Ctrl+C without exception trace

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <destination>", file=sys.stderr)
        sys.exit(1)

    logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))

    timeout = 5
    consecutive_timeout_limit = 10

    trace_destination = sys.argv[1].strip()
    try:
        # is it an IP address?
        trace_ip = IPv4Address(trace_destination)
    except ValueError:
        # try resolving it with DNS
        try:
            trace_ip = IPv4Address(socket.gethostbyname(trace_destination))
        except socket.gaierror as e:
            print(f"Could not resolve IPv4 address for {trace_destination}: {e}", file=sys.stderr)
            sys.exit(1)

    udp_send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    udp_send_sock.bind(("", 0)) # let the OS choose a source port

    icmp_recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    if os.name == "nt":
        # Required for ICMP socket on Windows
        host = socket.gethostbyname(socket.gethostname())
        icmp_recv_socket.bind((host, 0))
        icmp_recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        icmp_recv_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    only_timeouts = True
    timeouts = 0
    destination_port = 32768 - 1
    for ttl in range(1, sys.maxsize):
        destination_port += 1
        if destination_port >= 65536:
            destination_port = 32768

        traceroute_result = traceroute(trace_ip, destination_port, ttl, timeout, udp_send_sock, icmp_recv_socket)

        if traceroute_result is None:
            print(f"{ttl}. ?.?.?.? - No response within {timeout} seconds")
            timeouts += 1
            if timeouts >= consecutive_timeout_limit:
                print(f"Limit of {consecutive_timeout_limit} consecutive timeouts reached")
                break
            continue
        timeouts = 0
        only_timeouts = False

        hop_ip = traceroute_result.ip
        icmp_type = traceroute_result.icmp_type
        icmp_code = traceroute_result.icmp_code

        ip_info = get_ip_info(hop_ip, timeout)

        if traceroute_result.icmp_type == 3:
            icmp_response = ICMP_HUMAN_READABLE_NAMES.get((icmp_type, icmp_code), f"Type {icmp_type}, Code {icmp_code}")
            icmp_response_info = f", ICMP Response: {icmp_response}"
        else:
            icmp_response_info = ""

        print(f"{ttl}. {hop_ip} - {ip_info}{icmp_response_info}")

        if hop_ip == trace_ip:
            print("Reached destination")
            break

        if traceroute_result.icmp_type == 3:
            print("Last hop received Destination Unreachable, stopping traceroute")

    if only_timeouts:
        print("Never received any ICMP response during traceroute, check firewall settings")
        if os.name == "nt":
            print("Windows Firewall does not allow the necessary incoming ICMP responses by default")

    icmp_recv_socket.close()
    udp_send_sock.close()

if __name__ == "__main__":
    main()
