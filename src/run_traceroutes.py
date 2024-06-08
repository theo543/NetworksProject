import socket
import re
import subprocess
import sys
from pathlib import Path

DATA_FILE_NAME = "traceroute_ips.txt"
OUTPUT_FOLDER_NAME = "traceroute_results"
TRACEROUTE_SCRIPT_NAME = "traceroute.py"

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <network_name> [additional args for traceroute.py]")
        sys.exit(1)
    network_name = sys.argv[1]

    for line in (Path(__file__).parent / DATA_FILE_NAME).read_text().splitlines():
        line = line.strip()
        line_search = re.search(r"^(\d+\.\d+\.\d+\.\d+)(\s+[\w+\.\-]+)?$", line)
        if not line_search:
            if len(line) > 0 and not line.startswith("#"):
                print(f"Warning: Invalid line in {DATA_FILE_NAME}: {line}")
            continue

        ip_address = line_search.group(1)
        expected_domain = line_search.group(2)
        if expected_domain is not None:
            expected_domain = expected_domain.strip()
            try:
                if ip_address not in socket.gethostbyname_ex(expected_domain)[2]:
                    print(f"Warning: {ip_address} is not an IP address of {expected_domain}, it may no longer be in use.")
            except socket.gaierror:
                print(f"Warning: failed to resolve {expected_domain} to check if {ip_address} is still an IP address of it.")

        print(f"Launching traceroute for {ip_address}...")
        output_folder = Path(OUTPUT_FOLDER_NAME) / network_name
        output_file = output_folder / f"{ip_address}.txt"
        error_file = output_folder / f"{ip_address}_error.txt"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        assert sys.executable is not None
        script = Path(__file__).parent / TRACEROUTE_SCRIPT_NAME
        with output_file.open("w") as stdout, error_file.open("w") as stderr:
            # -u to disable buffering so output is seen in real time
            proc = subprocess.run([sys.executable, "-u", script, ip_address] + sys.argv[2:], stdout=stdout, stderr=stderr, check=False)
            if proc.returncode != 0:
                print(f"Warning: traceroute for {ip_address} returned exit code {proc.returncode}.")
        if error_file.stat().st_size == 0 and proc.returncode == 0:
            error_file.unlink()

if __name__ == "__main__":
    main()
