# Traceroute Results

The results are stored in the `traceroute_results` directory.
There is a different subdirectory for each network I ran the traceroutes from.

- `home` - my home network
- `networks_lab_vps` - an Oracle VPS
- `orange_mobile_data` - my mobile data connection
- `unibuc` - the university network (almost every hop was blocked)

The list of IPs traced from each location is stored in [traceroute_ips.txt](traceroute_ips.txt).
The file included the URLs from which the IPs were extracted.

Each hop which was able to be resolved to public IP addresses has the following information (if available):

- Country
- Region
- City
- Coordinates
- ISP
- Organization
- Autonomous System
- Reverse DNS
