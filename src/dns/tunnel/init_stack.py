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
    link = client_link_layer.ClientLinkLayer(listen_ip, listen_port, remote_ip, remote_port, domain_name, 20, 200)
    network = network_layer.NetworkLayer(200)
    transport = transport_layer.TransportLayer()
    link.register_network_interface(network)
    network.register_link_interface(link)
    network.register_transport_interface(transport)
    transport.register_network_interface(network)
    return transport

def init_dns_server_stack(listen_ip: str, listen_port: int, domain_name: DomainName) -> transport_layer.TransportLayer:
    link = server_link_layer.ServerLinkLayer(listen_ip, listen_port, domain_name, 30)
    network = network_layer.NetworkLayer(30)
    transport = transport_layer.TransportLayer()
    link.register_network_interface(network)
    network.register_link_interface(link)
    network.register_transport_interface(transport)
    transport.register_network_interface(network)
    return transport
