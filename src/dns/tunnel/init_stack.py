import logging
import sys
import os

from dns.packet import DomainName
from dns.tunnel import link_layer_dummy, network_layer, transport_layer, client_link_layer, server_link_layer

def init_dummy_stack(listen_ip: str, listen_port: int, remote_ip: str, remote_port: int) -> transport_layer.TransportLayer:
    link = link_layer_dummy.LinkLayerDummy(listen_ip, listen_port, remote_ip, remote_port)
    network = network_layer.NetworkLayer(200)
    transport = transport_layer.TransportLayer()
    link.register_network_interface(network)
    network.register_link_interface(link)
    network.register_transport_interface(transport)
    transport.register_network_interface(network)
    return transport

def init_dns_client_stack(listen_ip: str, listen_port: int, remote_ip: str, remote_port: int, domain_name: DomainName) -> transport_layer.TransportLayer:
    logging.info("Creating client stack with parameters: listen_ip=%s, listen_port=%d, remote_ip=%s, remote_port=%d, domain_name=%s",
                listen_ip, listen_port, remote_ip, remote_port, domain_name)
    link = client_link_layer.ClientLinkLayer(listen_ip, listen_port, remote_ip, remote_port, domain_name, 30, 100)
    network = network_layer.NetworkLayer(30)
    transport = transport_layer.TransportLayer()
    link.register_network_interface(network)
    network.register_link_interface(link)
    network.register_transport_interface(transport)
    transport.register_network_interface(network)
    return transport

def init_dns_server_stack(listen_ip: str, listen_port: int, domain_name: DomainName) -> transport_layer.TransportLayer:
    logging.info("Creating server stack with parameters: listen_ip=%s, listen_port=%d, domain_name=%s", listen_ip, listen_port, domain_name)
    link = server_link_layer.ServerLinkLayer(listen_ip, listen_port, domain_name, 30, 150)
    network = network_layer.NetworkLayer(30)
    transport = transport_layer.TransportLayer()
    link.register_network_interface(network)
    network.register_link_interface(link)
    network.register_transport_interface(transport)
    transport.register_network_interface(network)
    return transport

def init_dns_tunnel_stack_from_argv() -> tuple[transport_layer.TransportLayer, int]:
    def usage():
        print(f"Usage: {sys.argv[0]} <domain_name> <active|passive> <src_ip> <src_port> [<dst_ip> <dst_port>]")
    try:
        logging.basicConfig(level=logging.INFO if not os.getenv("LOGLEVEL") else os.getenv("LOGLEVEL"))
        domain_name = DomainName.from_str(sys.argv[1])
        active = sys.argv[2]
        src_ip = sys.argv[3]
        src_port = int(sys.argv[4])
        if active == "active":
            dst_ip = sys.argv[5]
            dst_port = int(sys.argv[6])
            return init_dns_client_stack(src_ip, src_port, dst_ip, dst_port, domain_name), 6
        if active == "passive":
            return init_dns_server_stack(src_ip, src_port, domain_name), 4
        raise ValueError("Invalid mode: " + active)
    except (IndexError, ValueError):
        usage()
        sys.exit(1)
