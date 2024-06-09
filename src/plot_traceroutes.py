import sys
import re
from pathlib import Path
from ipaddress import IPv4Address
import requests

from matplotlib import pyplot as plt
from mpl_toolkits import basemap

TIMEOUT = 10

def get_saved_route(file: Path) -> list[tuple[int, int, bool]]:
    target_ip = IPv4Address(file.stem)
    if target_ip.is_private:
        return []
    route = []
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
        route.append((lat, lon, False))
        last_ip = hop_ip
    if last_ip != target_ip:
        query_url = f"http://ip-api.com/json/{target_ip}?fields=status,lat,lon"
        headers = {"User-Agent": "Traceroute Map Plotter Script"}
        response = requests.get(query_url, headers=headers, timeout=TIMEOUT)
        assert response.status_code == 200
        status = response.json()["status"]
        assert status == "success"
        lat = response.json()["lat"]
        lon = response.json()["lon"]
        route.append((lat, lon, True))
    return route

def main():
    if len(sys.argv) < 2:
        print("Usage: python plot_traceroutes.py <results_folder>")
        sys.exit(1)

    routes: list[list[tuple[int, int, bool]]] = []

    results_folder = Path(sys.argv[1])
    for subfolder in results_folder.iterdir():
        if not subfolder.is_dir():
            continue

        for file in subfolder.iterdir():
            if file.suffix == ".txt":
                routes.append(get_saved_route(file))

    # plot all routes on a map
    bmap = basemap.Basemap(projection="merc")
    bmap.drawcoastlines()
    cmap = plt.get_cmap("tab20")
    routes.sort(key=len, reverse=True)
    for route_i, route in enumerate(routes):
        for prev_hop, hop in zip(route, route[1:]):
            from_x, from_y, _ = prev_hop
            to_x, to_y, target_did_not_respond = hop
            plt.plot([from_x, to_x], [from_y, to_y], color=cmap(route_i))
    plt.show()

if __name__ == "__main__":
    main()
