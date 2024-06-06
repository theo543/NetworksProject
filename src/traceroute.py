import socket
import os
import sys
import signal
import time
from ipaddress import IPv4Address

import requests

USER_AGENT = "UDP Traceroute Homework for Networks course at University of Bucharest (https://networks.hypha.ro/)"
USER_AGENT_B = USER_AGENT.encode("ascii")

# cSpell: ignoreRegExp socket.\w+

def get_ip_info(ip: IPv4Address, timeout: int) -> str:
    if ip.is_private:
        return "No IP info available: private range"

    header = {"user-agent": USER_AGENT}
    query_url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as"
    try:
        response = requests.get(query_url, headers=header, timeout=timeout)
    except requests.exceptions.RequestException as e:
        return f"No IP info available: Got exception {e.__class__.__name__} when sending request to API, exception message: {e}"

    if response.status_code != 200:
        print(f"Non-200 status code {response.status_code} from query at {query_url}", file=sys.stderr)
        return f"No IP info available: Got status code {response.status_code} from API"

    try:
        ip_info = response.json()
    except requests.exceptions.JSONDecodeError:
        return "No IP info available: Could not decode JSON response from API"

    assert isinstance(ip_info, dict)
    if ip_info["status"] != "success":
        return f"No IP info available: {ip_info['message']}"

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

    return f"{country}, {region}, {city}, {isp}, {org}, {as_}"

class UDPSendError(Exception):
    pass

def traceroute(ip: IPv4Address, ttl: int, timeout: int, udp_send_sock: socket.socket, icmp_recv_socket: socket.socket) -> IPv4Address | None:
    udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    source_port = udp_send_sock.getsockname()[1] # socket name is (ip, port)
    destination_port = 32768

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
            continue

        icmp_header = data[ihl * 4:ihl * 4 + 8]
        icmp_data = data[ihl * 4 + 8:]
        icmp_type = icmp_header[0]
        icmp_code = icmp_header[1]
        # TODO: calculate checksum and check if it's correct

        if not ((icmp_type == 11 and icmp_code == 0) or icmp_type == 3):
            continue

        embedded_ihl_version = icmp_data[0]
        embedded_version = embedded_ihl_version >> 4
        embedded_ihl = embedded_ihl_version & (0b1111)
        embedded_protocol = icmp_data[9]

        if not (embedded_version == 4 and embedded_ihl >= 5 and embedded_protocol == socket.IPPROTO_UDP):
            continue

        embedded_udp_header = icmp_data[embedded_ihl * 4:embedded_ihl * 4 + 8]
        embedded_udp_source_port = int.from_bytes(embedded_udp_header[0:2], "big")
        embedded_udp_destination_port = int.from_bytes(embedded_udp_header[2:4], "big")
        embedded_udp_length = int.from_bytes(embedded_udp_header[4:6], "big")
        # TODO: embedded_udp_checksum = int.from_bytes(embedded_udp_header[6:8], "big")
        embedded_udp_data = icmp_data[embedded_ihl * 4 + 8:]

        if not (embedded_udp_source_port == source_port and embedded_udp_destination_port == destination_port and embedded_udp_length == sent_udp_length):
            continue

        if not USER_AGENT_B.startswith(embedded_udp_data):
            continue

        return IPv4Address(addr)

    return None

def main():
    signal.signal(signal.SIGINT, lambda _signal, _frame: sys.exit(1)) # exit on Ctrl+C without exception trace

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
            print(f"Could not resolve IPv4 address for {trace_destination}: {e}")
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
    for ttl in range(1, sys.maxsize):
        hop_ip = traceroute(trace_ip, ttl, timeout, udp_send_sock, icmp_recv_socket)
        if hop_ip is None:
            ip_info = f"No response within {timeout} seconds"
            timeouts += 1
        else:
            ip_info = get_ip_info(hop_ip, timeout)
            timeouts = 0
            only_timeouts = False
        placeholder = "?.?.?.?"
        print(f"{ttl}. {hop_ip or placeholder} - {ip_info}")
        if hop_ip == trace_ip:
            print("Reached destination")
            break
        if timeouts >= consecutive_timeout_limit:
            print(f"Limit of {consecutive_timeout_limit} consecutive timeouts reached")
            break
    if only_timeouts:
        print("Never received any ICMP response during traceroute, check firewall settings")
        if os.name == "nt":
            print("Windows Firewall does not allow the necessary incoming ICMP responses by default")

    icmp_recv_socket.close()
    udp_send_sock.close()

if __name__ == "__main__":
    main()
