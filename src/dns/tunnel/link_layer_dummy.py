import socket
from collections import deque
from threading import Thread
import time
import logging

from dns.tunnel.interfaces import LinkLayerInterface, NetworkLayerInterface

class LinkLayerDummy(LinkLayerInterface):
    link: socket.socket
    network: NetworkLayerInterface | None = None
    send_queue: deque[bytes]
    thread: Thread
    listen_addr: str
    listen_port: int
    destination_addr: str
    destination_port: int

    def _run_thread(self):
        while True:
            if self.network is None:
                time.sleep(0.1)
                continue
            if len(self.send_queue) > 0:
                self.link.settimeout(0.01)
                logging.info("Link layer sending one PDU, %d PDUs in queue", len(self.send_queue))
                self.link.sendall(self.send_queue.popleft())
            else:
                self.link.settimeout(0.1)
            try:
                data, _addr = self.link.recvfrom(1024)
                logging.info("Link layer received 1 PDU")
                self.network.receive_from_link_layer([data])
            except socket.timeout:
                pass

    def __init__(self, listen_addr: str, listen_port: int, destination_addr: str, destination_port: int):
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.destination_addr = destination_addr
        self.destination_port = destination_port
        self.link = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.link.bind((listen_addr, listen_port))
        self.link.connect((destination_addr, destination_port))
        self.send_queue = deque(maxlen=1024)
        self.thread = Thread(target=self._run_thread)
        self.thread.daemon = True
        self.thread.start()

    def register_network_interface(self, interface: NetworkLayerInterface):
        self.network = interface

    def queue_transmission_from_network_layer(self, network_pdus: list[bytes]):
        logging.info("Link layer queued %d PDUs", len(network_pdus))
        for pdu in network_pdus:
            self.send_queue.append(pdu)
