import random
import logging

from dns.tunnel.transport_layer import TransportLayerInterface

def ping(transport: TransportLayerInterface, destination_port: int):
    message = bytes(random.getrandbits(8) for _ in range(2000))
    ping_socket = transport.create_datagram_socket(0)
    ping_socket.push_data(message, destination_port)
    logging.info(f"Sent data to port {destination_port}")
    while True:
        source_port, data = ping_socket.pop_data()
        print(f"Received data from port {source_port}")
        if source_port == destination_port and data == message:
            print("Received expected data")
            break
        else:
            print("Received unexpected data")

def server(transport: TransportLayerInterface, listen_port: int):
    server_socket = transport.create_datagram_socket(listen_port)
    logging.info(f"Listening on port {listen_port}")
    while True:
        source_port, data = server_socket.pop_data()
        logging.info(f"Received and echoing data from port {source_port}")
        server_socket.push_data(data, source_port)
