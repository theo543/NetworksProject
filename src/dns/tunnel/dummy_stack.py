from dns.tunnel import link_layer_dummy, network_layer, transport_layer

def init_dummy_stack(listen_ip: str, listen_port: int, remote_ip: str, remote_port: int) -> transport_layer.TransportLayer:
    link = link_layer_dummy.LinkLayerDummy(listen_ip, listen_port, remote_ip, remote_port)
    network = network_layer.NetworkLayer(200)
    transport = transport_layer.TransportLayer()
    link.register_network_interface(network)
    network.register_link_interface(link)
    network.register_transport_interface(transport)
    transport.register_network_interface(network)
    return transport
