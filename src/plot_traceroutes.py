import sys
import re
from pathlib import Path
from ipaddress import IPv4Address
import requests

from matplotlib import pyplot as plt
from mpl_toolkits import basemap

TIMEOUT = 10

BUCHAREST_COORDS = (44.4268, 26.1025)
FRANKFURT_COORDS = (50.1109, 8.6821)

def get_saved_route(file: Path) -> tuple[list[tuple[float, float]], bool] | None:
    target_ip = IPv4Address(file.stem)
    if target_ip.is_private:
        return None
    route: list[tuple[float, float]] = [BUCHAREST_COORDS]
    last_ip: IPv4Address | None = None
    for line in file.read_text().splitlines():
        search = re.search(r"^\d+\. (\d+\.\d+\.\d+\.\d+) - (.+)$", line)
        if not search:
            continue
        hop_ip = IPv4Address(search.group(1))
        if hop_ip.is_private:
            continue
        result = search.group(2)
        if result.startswith("No IP info available: "):
            continue
        search_coords = re.search(r"^Country: \".*?\", Region: \".*?\", City: \".*?\", (-?\d+(?:\.\d+)?), (-?\d+(?:\.\d+)?)", result)
        assert search_coords
        lat = float(search_coords.group(1))
        lon = float(search_coords.group(2))
        route.append((lat, lon))
        last_ip = hop_ip
    last_was_missing = last_ip != target_ip
    if last_was_missing:
        query_url = f"http://ip-api.com/json/{target_ip}?fields=status,lat,lon"
        headers = {"User-Agent": "Traceroute Map Plotter Script"}
        response = requests.get(query_url, headers=headers, timeout=TIMEOUT)
        assert response.status_code == 200
        status = response.json()["status"]
        assert status == "success"
        lat = response.json()["lat"]
        lon = response.json()["lon"]
        route.append((lat, lon))
    return route, last_was_missing

def main():
    if len(sys.argv) < 2:
        print("Usage: python plot_traceroutes.py <results_folder>")
        sys.exit(1)

    routes: list[tuple[list[tuple[float, float]], bool]] = []

    results_folder = Path(sys.argv[1])
    for file in results_folder.iterdir():
        if file.suffix == ".txt":
            r = get_saved_route(file)
            if r is not None:
                routes.append(r)

    coords = BUCHAREST_COORDS if "vps" not in results_folder.name else FRANKFURT_COORDS
    bmap = basemap.Basemap()
    bmap.drawcoastlines()
    routes.sort(reverse=True, key = lambda x: len(x[0]))
    plt.plot(coords[1], coords[0], "ro")
    def arrow(x1, y1, x2, y2, linestyle="-", alpha=1.0):
        plt.arrow(x1, y1, x2 - x1, y2 - y1, color="blue", head_width=1, head_length=2, length_includes_head=True, linestyle=linestyle, alpha=alpha)
    for (route, end_was_missing) in routes:
        first_y, first_x = route[0]
        last_y, last_x = None, None
        arrow(coords[1], coords[0], first_x, first_y)
        if end_was_missing:
            last_y, last_x = route[-1]
            route = route[:-1]
        for prev_hop, hop in zip(route[1:], route[2:]):
            from_y, from_x = prev_hop
            to_y, to_x = hop
            arrow(from_x, from_y, to_x, to_y)
        if last_x is not None and last_y is not None and len(route) >= 1:
            arrow(route[-1][1], route[-1][0], last_x, last_y, linestyle="--", alpha=0.5)
    plt.show()

if __name__ == "__main__":
    main()
