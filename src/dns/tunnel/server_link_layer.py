import socket
from collections import deque
from threading import Thread
import time
import logging

from dns.tunnel.interfaces import LinkLayerInterface, NetworkLayerInterface
from dns.tunnel.link_layer_format import base36_to_bin_array, bin_array_to_bin, LinkLayerMalformedData
from dns.packet import DNSPacket, DNSResourceRecord, DomainName, ResponseCode, labels_eq

class ServerLinkLayer(LinkLayerInterface):
    link: socket.socket
    network: NetworkLayerInterface | None = None
    send_queue: deque[bytes]
    thread: Thread
    listen_addr: str
    listen_port: int
    destination_addr: str | None
    destination_port: int
    response_max_size: int
    fragment_max_size: int
    domain_name: DomainName
    pending_requests: set[int]

    def _run_thread(self):
        while True:
            time.sleep(0.1)
            if self.network is None:
                continue
            try:
                request, addr = self.link.recvfrom(1024)
                logging.debug("Link layer received DNS request")
                request = DNSPacket.from_bytes(request)
                data = None
                for query in request.questions:
                    needed_domain = self.domain_name.labels
                    if labels_eq(query.name.labels[-len(needed_domain):], needed_domain):
                        encoded = bytearray()
                        for label in query.name.labels[:-len(needed_domain)]:
                            encoded += label
                        try:
                            data = base36_to_bin_array(bytes(encoded))
                        except LinkLayerMalformedData:
                            logging.warning("Could not decode DNS request")
                            continue
                        logging.info("Link layer received tunnel DNS request from %s:%d", addr[0], addr[1])
                        self.destination_addr = addr[0]
                        self.destination_port = addr[1]
                        break
                if data is None:
                    logging.debug("Link layer received non-tunnel DNS request")
                    continue
                self.network.receive_from_link_layer(data)
                fragments: list[bytes] = []
                frag_size = 0
                logging.info("Collecting fragments for DNS response")
                while frag_size + self.fragment_max_size < self.response_max_size and len(self.send_queue) > 0:
                    fragments.append(self.send_queue.popleft())
                    frag_size += len(fragments[-1])
                if len(self.send_queue) != 0:
                    logging.info("Was unable to send all PDUs in one DNS response, max response size is %d, fragments size is %d, was able to pack %d fragments",
                                    self.response_max_size, frag_size, len(fragments))
                    logging.info("PDUs left in queue: %d", len(self.send_queue))
                logging.debug("Link layer sending %d fragments in one DNS response, %d PDUs in queue", len(fragments), len(self.send_queue))
                request = DNSPacket(
                    request_id=request.request_id,
                    is_response=True,
                    authoritative_answer=True,
                    truncation=False,
                    recursion_desired=request.recursion_desired,
                    reserved=0,
                    recursion_available=False,
                    response_code=ResponseCode.NO_ERROR,
                    questions=[],
                    answers=[DNSResourceRecord(
                        name = request.questions[0].name,
                        ttl = 0,
                        class_ = 16,
                        type_ = 1,
                        data = bin_array_to_bin(fragments)
                    )],
                    authorities=[],
                    additional=[]
                )
                logging.debug("Sending a response of %d bytes to %s:%d", len(request.to_bytes()), addr[0], addr[1])
                response = request.to_bytes()
                self.link.sendto(response, addr)
            except socket.timeout:
                continue

    def __init__(self, listen_addr: str, listen_port: int, domain_name: DomainName, fragment_max_size: int, response_max_size: int):
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.destination_addr = None
        self.destination_port = 0
        self.pending_requests = set()
        self.link = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.link.bind((listen_addr, listen_port))
        self.fragment_max_size = fragment_max_size
        self.send_queue = deque(maxlen=1024)
        self.domain_name = domain_name
        self.response_max_size = response_max_size
        self.thread = Thread(target=self._run_thread)
        self.thread.daemon = True
        self.thread.start()

    def register_network_interface(self, interface: NetworkLayerInterface):
        self.network = interface

    def queue_transmission_from_network_layer(self, network_pdus: list[bytes]):
        logging.info("Link layer queued %d PDUs", len(network_pdus))
        for pdu in network_pdus:
            self.send_queue.append(pdu)
