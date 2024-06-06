import socket
import os
import sys
import signal
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

def traceroute(ip: IPv4Address, ttl: int, udp_send_sock: socket.socket, icmp_recv_socket: socket.socket) -> IPv4Address | None:
    udp_send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    destination_port = 65535

    content = USER_AGENT_B
    bytes_sent = udp_send_sock.sendto(content, (str(ip), destination_port))
    if bytes_sent != len(content):
        raise UDPSendError(f"Could not send all {len(content)} bytes to {ip}:{destination_port}")
    try:
        # TODO: check _data to see if the response is TTL exceeded, destination unreachable, or port unreachable
        # TODO: TTL exceeded includes source, destination, length, checksum, check if it's from this traceroute
        # TODO: some routers send more than 8 bytes even though only 8 are required, if so check that as well
        _data, (addr, _port) = icmp_recv_socket.recvfrom(63535)
        return IPv4Address(addr)
    except TimeoutError as _e:
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
    icmp_recv_socket.settimeout(timeout)

    if os.name == "nt":
        # Required for ICMP socket on Windows
        # TODO: this is not enough to work on Windows, WireShark shows the TTL exceeded packets arrive but the socket does not receive them
        print("WARNING: traceroute.py appears not to receive ICMP TTL exceeded packets on Windows, likely won't work")
        host = socket.gethostbyname(socket.gethostname())
        icmp_recv_socket.bind((host, 0))
        icmp_recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        icmp_recv_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    timeouts = 0
    for ttl in range(1, sys.maxsize):
        hop_ip = traceroute(trace_ip, ttl, udp_send_sock, icmp_recv_socket)
        if hop_ip is None:
            ip_info = f"No response within {timeout} seconds"
            timeouts += 1
        else:
            ip_info = get_ip_info(hop_ip, timeout)
            timeouts = 0
        placeholder = "?.?.?.?"
        print(f"{ttl}. {hop_ip or placeholder} - {ip_info}")
        if hop_ip == trace_ip:
            print("Reached destination")
            break
        if timeouts >= consecutive_timeout_limit:
            print(f"Limit of {consecutive_timeout_limit} consecutive timeouts reached")
            break

    icmp_recv_socket.close()
    udp_send_sock.close()

if __name__ == "__main__":
    main()
