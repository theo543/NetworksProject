import socket
from collections import deque
from threading import Thread
import time
import logging
import random

from dns.tunnel.interfaces import LinkLayerInterface, NetworkLayerInterface
from dns.tunnel.link_layer_format import bin_array_to_base36, bin_to_bin_array
from dns.packet import DNSPacket, DNSQuestion, DomainName, ResponseCode, labels_eq


class ClientLinkLayer(LinkLayerInterface):
    link: socket.socket
    network: NetworkLayerInterface | None = None
    send_queue: deque[bytes]
    thread: Thread
    listen_addr: str
    listen_port: int
    destination_addr: str
    destination_port: int
    query_max_size: int
    fragment_max_size: int
    domain_name: DomainName
    pending_requests: set[int]
    time_since_last_send: float = 0

    def _run_thread(self):
        labels = self.domain_name.labels
        while True:
            time.sleep(0.1)
            if self.network is None:
                continue
            if len(self.send_queue) > 0 or time.time() - self.time_since_last_send > 0.2:
                self.link.settimeout(0.01)
                data: list[bytes] = []
                domain_name_bin = self.domain_name.to_bytes()
                data_size = len(domain_name_bin) + 2
                while (data_size + self.fragment_max_size) < self.query_max_size and len(self.send_queue) > 0:
                    data.append(self.send_queue.popleft())
                    data_size += len(data[-1])
                logging.debug("Link layer sending one PDU, %d PDUs in queue", len(self.send_queue))
                url_encoded_data = bin_array_to_base36(data)
                logging.debug("Encoded %d bytes to %d characters", sum(len(x) for x in data), len(url_encoded_data))
                encoded_labels = [url_encoded_data[i:i+63] for i in range(0, len(url_encoded_data), 63)]
                query_name = [*encoded_labels, *self.domain_name.labels]
                query = DNSQuestion (
                    name = DomainName(query_name),
                    qtype = 1,
                    qclass = 16
                )
                req = random.randint(0, 65535)
                self.pending_requests.add(req)
                packet = DNSPacket(
                    request_id=req,
                    is_response=False,
                    authoritative_answer=False,
                    truncation=False,
                    recursion_desired=True,
                    reserved=0,
                    recursion_available=False,
                    response_code=ResponseCode.NO_ERROR,
                    questions=[query],
                    answers=[],
                    authorities=[],
                    additional=[],
                )
                query_encoded_data = packet.to_bytes()
                self.link.sendall(query_encoded_data)
                self.time_since_last_send = time.time()
                logging.debug("Link layer sent DNS request of %d bytes", len(query_encoded_data))
            else:
                self.link.settimeout(0.1)
            try:
                try:
                    response, _addr = self.link.recvfrom(1024)
                except ConnectionResetError:
                    logging.warning("Received ICMP for a previous request")
                    time.sleep(1)
                    continue
                logging.debug("Link layer received DNS response")
                response = DNSPacket.from_bytes(response)
                if response.request_id not in self.pending_requests:
                    logging.warning("Received response with unknown request ID")
                    continue
                self.pending_requests.remove(response.request_id)
                if response.response_code != ResponseCode.NO_ERROR:
                    logging.warning("Received response with error code %s", response.response_code)
                    continue
                for answer in response.answers:
                    if answer.type_ == 1 and answer.class_ == 1 and labels_eq(answer.name.labels[-len(labels):], labels):
                        logging.debug("Link layer received %d bytes", len(answer.data))
                        data = bin_to_bin_array(answer.data)
                        logging.debug("Link layer decoded %d PDUs", len(data))
                        self.network.receive_from_link_layer(data)
            except socket.timeout:
                continue

    def __init__(self, listen_addr: str, listen_port: int, destination_addr: str, destination_port: int, domain_name: DomainName, fragment_max_size: int, query_max_size: int):
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.destination_addr = destination_addr
        self.destination_port = destination_port
        self.pending_requests = set()
        try:
            socket.inet_pton(socket.AF_INET6, listen_addr)
            socket.inet_pton(socket.AF_INET6, destination_addr)
            self.link = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        except OSError:
            self.link = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.link.bind((listen_addr, listen_port))
        self.link.connect((destination_addr, destination_port))
        self.fragment_max_size = fragment_max_size
        self.send_queue = deque(maxlen=1024)
        self.domain_name = domain_name
        self.query_max_size = query_max_size
        self.thread = Thread(target=self._run_thread)
        self.thread.daemon = True
        self.thread.start()

    def register_network_interface(self, interface: NetworkLayerInterface):
        self.network = interface

    def queue_transmission_from_network_layer(self, network_pdus: list[bytes]):
        logging.info("Link layer queued %d PDUs", len(network_pdus))
        for pdu in network_pdus:
            self.send_queue.append(pdu)
