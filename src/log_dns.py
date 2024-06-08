import sys
from dns import log_dns

log_dns.log_server(sys.argv[1], int(sys.argv[2]))
