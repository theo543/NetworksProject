from __future__ import annotations

from collections import deque
import random
from threading import Condition, Event, Lock, Thread
import logging
import time
from zlib import crc32

from dns.tunnel.interfaces import TransportLayerInterface, NetworkLayerInterface, DatagramSocketInterface, StreamSocketInterface

# Transport layer 
# 2 bytes: source port
# 2 bytes: destination port
# 1 byte: protocol
# variable: datagram or stream data

class TransportLayer(TransportLayerInterface):
    network: NetworkLayerInterface | None = None
    datagram_sockets: dict[int, DatagramSocket]
    stream_sockets: dict[tuple[int, int], StreamSocket]
    stream_listening_accepts: dict[int, tuple[Event, list[StreamSocket]]] # socket will be put in list when accepted
    recently_used_ports: dict[int, float]
    stream_mtu: int
    big_lock: Lock

    def __init__(self):
        self.datagram_sockets = {}
        self.stream_sockets = {}
        self.stream_listening_accepts = {}
        self.recently_used_ports = {}
        self.big_lock = Lock()
        self.stream_mtu = 100

    def _find_ephemeral_port(self) -> int:
        while True:
            port = random.randint(0b1000000000000000, 0b1111111111111111)
            if port not in self.recently_used_ports and port not in self.datagram_sockets:
                return port

    def _send_to_network_layer(self, pdu: bytes, source_port: int, destination_port: int, is_stream: bool):
        if self.network is None:
            logging.warning("Network layer not registered with transport layer")
            return
        pdu = source_port.to_bytes(2, "big") + destination_port.to_bytes(2, "big") + is_stream.to_bytes(1, "big") + pdu
        self.network.queue_transmission_from_transport_layer(pdu)

    def register_network_interface(self, interface: NetworkLayerInterface):
        self.network = interface

    def receive_from_network_layer(self, transport_pdu: bytes):
        if len(transport_pdu) < 4:
            logging.warning("Transport PDU too short")
            return
        logging.info("Received transport PDU from network layer")
        source_port = int.from_bytes(transport_pdu[:2], "big")
        destination_port = int.from_bytes(transport_pdu[2:4], "big")
        is_stream = bool(transport_pdu[4])
        pdu = transport_pdu[5:]
        with self.big_lock:
            if is_stream:
                logging.info("Listening ports: %s", str(self.stream_listening_accepts.keys()))
                if (source_port, destination_port) in self.stream_sockets:
                    sock = self.stream_sockets[(source_port, destination_port)]
                    sock.received_pdus.append(pdu)
                    logging.info("Delivered PDU to stream socket on port %d connected to port %d, now contains %d PDUs", source_port, destination_port, len(sock.received_pdus))
                elif destination_port in self.stream_listening_accepts:
                    (event, box) = self.stream_listening_accepts[destination_port]
                    box.append(StreamSocket._init_from_accept(source_port, destination_port, self))
                    self.stream_listening_accepts.pop(destination_port)
                    self.stream_sockets[(source_port, destination_port)] = box[0]
                    event.set()
                    logging.info("Accepted connection on port %d", destination_port)
                else:
                    logging.warning("No socket listening on destination stream port %d", destination_port)
            else:
                if destination_port in self.datagram_sockets:
                    logging.info("PDU is datagram for socket on port %d", destination_port)
                    sock = self.datagram_sockets[destination_port]
                    with sock.received_datagrams_cv:
                        sock.received_datagrams.append((source_port, pdu))
                        sock.received_datagrams_cv.notify_all()
                else:
                    logging.warning("No socket listening on destination datagram port %d", destination_port)

    def accept_stream_connection(self, listen_port: int) -> StreamSocket:
        with self.big_lock:
            if listen_port in self.stream_listening_accepts:
                raise ValueError("Already listening on port")
            event = Event()
            box: list[StreamSocket] = []
            self.stream_listening_accepts[listen_port] = (event, box)
            logging.info("Listening on port %d", listen_port)
        event.wait()
        logging.info("Accepted connection on port %d", listen_port)
        return box.pop()

    def connect_stream(self, destination_port: int) -> StreamSocket:
        with self.big_lock:
            source_port = self._find_ephemeral_port()
            sock = StreamSocket._init_as_client(source_port, destination_port, self)
            self.stream_sockets[(source_port, destination_port)] = sock
        return sock

    def create_datagram_socket(self, source_port: int) -> DatagramSocketInterface:
        with self.big_lock:
            if source_port == 0:
                logging.info("Creating datagram socket on ephemeral port")
                source_port = self._find_ephemeral_port()
                logging.info("Ephemeral port is %d", source_port)
            if source_port in self.datagram_sockets:
                raise ValueError("Port already in use")
            sock = DatagramSocket(self, source_port)
            self.datagram_sockets[source_port] = sock
        return sock

class DatagramSocket(DatagramSocketInterface):
    transport: TransportLayer
    source_port: int
    received_datagrams: deque[tuple[int, bytes]]
    received_datagrams_lock: Lock
    received_datagrams_cv: Condition

    def __init__(self, transport: TransportLayer, source_port: int):
        self.transport = transport
        self.source_port = source_port
        self.received_datagrams = deque(maxlen=1024)
        self.received_datagrams_lock = Lock()
        self.received_datagrams_cv = Condition(self.received_datagrams_lock)

    def pop_data(self) -> tuple[int, bytes]:
        """
        Return datagram source port and data.
        """
        def data_available():
            return len(self.received_datagrams) != 0
        with self.received_datagrams_cv:
            self.received_datagrams_cv.wait_for(data_available)
            data = self.received_datagrams.popleft()
        logging.info("Popped datagram from datagram socket on port %d", self.source_port)
        return data

    def push_data(self, data: bytes, destination_port: int):
        with self.transport.big_lock:
            self.transport._send_to_network_layer(data, self.source_port, destination_port, False)

    def close(self):
        with self.transport.big_lock:
            self.transport.datagram_sockets.pop(self.source_port)
            self.transport.recently_used_ports[self.source_port] = time.time()

# Stream layout:
# 4 bytes: CRC32
# 4 bytes: acknowledgement of previously sent transmission ID
# 4 bytes: optional transmission ID
# variable: data, if transmission ID is present

class StreamSocket(StreamSocketInterface):
    transport: TransportLayer
    source_port: int
    destination_port: int
    received_bytes_lock: Lock
    received_bytes_cv: Condition
    received_bytes: bytes
    last_received_transmission_id: int
    pending_transmission_lock: Lock
    pending_transmission_cv: Condition
    pending_transmission: bytes
    currently_transmitting: bytes # saved in case of retransmission
    currently_transmitting_id: int
    data_transmitted_at: float
    ack_transmitted_at: float
    stream_window_size: int
    received_pdus: deque[bytes]
    closing: bool
    thread: Thread

    def __init__(self, transport: TransportLayer, source_port: int, destination_port: int):
        logging.info("Creating stream socket from %d to %d", source_port, destination_port)
        self.transport = transport
        self.received_bytes = bytes()
        self.pending_transmission = bytes()
        self.received_pdus = deque()
        self.received_bytes_lock = Lock()
        self.received_bytes_cv = Condition(self.received_bytes_lock)
        self.last_received_transmission_id = 0
        self.pending_transmission_lock = Lock()
        self.pending_transmission_cv = Condition(self.pending_transmission_lock)
        self.source_port = source_port
        self.destination_port = destination_port
        self.currently_transmitting = bytes()
        self.currently_transmitting_id = 1
        self.data_transmitted_at = 0
        self.ack_transmitted_at = 0
        self.stream_window_size = 100
        self.closing = False
        self.thread = Thread(target=self._run_thread)
        self.thread.daemon = True
        self.thread.start()
        logging.info("Stream socket created")

    @classmethod
    def _init_from_accept(cls, source_port: int, destination_port: int, transport: TransportLayer) -> StreamSocket:
        self = StreamSocket(transport, source_port, destination_port)
        return self

    @classmethod
    def _init_as_client(cls, source_port: int, destination_port: int, transport: TransportLayer) -> StreamSocket:
        #starting_packet = (0).to_bytes(4, "big") + (0).to_bytes(4, "big")
        #crc = crc32(starting_packet).to_bytes(4, "big")
        #pdu = crc + starting_packet
        #logging.info("Sending initial packet to port %d", destination_port)
        #transport._send_to_network_layer(pdu, source_port, destination_port, True)
        self = StreamSocket(transport, source_port, destination_port)
        return self

    def pop_data(self, amount: int, min_amount: int | None = None) -> bytes:
        if self.closing:
            raise ValueError("Socket is closing")
        if min_amount is None:
            min_amount = amount
        def data_available():
            return len(self.received_bytes) >= min_amount
        with self.received_bytes_cv:
            self.received_bytes_cv.wait_for(data_available)
            data = self.received_bytes[:amount]
            self.received_bytes = self.received_bytes[amount:]
        return data

    def push_data(self, data: bytes):
        if self.closing:
            raise ValueError("Socket is closing")
        logging.info("Pushing data to stream socket")
        with self.pending_transmission_cv:
            logging.info("Acquired pending transmission lock")
            self.pending_transmission += data
            self.pending_transmission_cv.notify_all()

    def close(self):
        logging.info("Closing stream socket from %d to %d", self.source_port, self.destination_port)
        while len(self.pending_transmission) > 0:
            logging.info("Waiting for pending transmission to finish")
            time.sleep(0.1)
        self.closing = True

    def _run_thread(self):
        while not self.closing:
            to_sleep = 0.1
            while len(self.received_pdus) > 0:
                pdu = self.received_pdus.popleft()
                to_sleep = 0.01
                crc = int.from_bytes(pdu[:4], "big")
                ack = int.from_bytes(pdu[4:8], "big")
                transmission_id = int.from_bytes(pdu[8:12], "big")
                data = pdu[12:]
                if crc32(pdu[4:]) != crc:
                    logging.warning("CRC32 mismatch at transport layer")
                    continue
                if ack == self.currently_transmitting_id:
                    logging.info("Received acknowledgement for transmission ID %d", ack)
                    self.currently_transmitting = bytes()
                    self.currently_transmitting_id += 1
                elif ack != self.currently_transmitting_id - 1:
                    logging.warning("Received acknowledgement for transmission ID %d, currently transmitting ID %d", ack, self.currently_transmitting_id)
                if transmission_id == self.last_received_transmission_id + 1:
                    logging.info("Received transmission ID %d", transmission_id)
                    self.last_received_transmission_id += 1
                    with self.received_bytes_cv:
                        self.received_bytes += data
                        self.received_bytes_cv.notify_all()
                    self.ack_transmitted_at = 0 # force transmission to send ack
                elif transmission_id != 0:
                    logging.warning("Received out-of-order transmission ID %d, expected %d, connection may be broken", transmission_id, self.last_received_transmission_id + 1)
            if len(self.pending_transmission) > 0 and len(self.currently_transmitting) == 0:
                with self.pending_transmission_cv:
                    self.currently_transmitting = self.pending_transmission[:self.stream_window_size]
                    self.pending_transmission = self.pending_transmission[self.stream_window_size:]
                    self.data_transmitted_at = 0
                logging.info("Moved %d bytes to currently transmitting buffer, transmission ID %d", len(self.currently_transmitting), self.currently_transmitting_id)
            if len(self.currently_transmitting) > 0 and time.time() - self.data_transmitted_at > 1:
                logging.info("Sending transmission ID %d", self.currently_transmitting_id)
                to_sleep = 0.01
                pdu = self.last_received_transmission_id.to_bytes(4, "big") + self.currently_transmitting_id.to_bytes(4, "big") + self.currently_transmitting
                pdu = crc32(pdu).to_bytes(4, "big") + pdu
                self.transport._send_to_network_layer(pdu, self.source_port, self.destination_port, True)
                self.data_transmitted_at = time.time()
            elif time.time() - self.ack_transmitted_at > 10:
                pdu = self.last_received_transmission_id.to_bytes(4, "big") + b"\x00\x00\x00\x00"
                pdu = crc32(pdu).to_bytes(4, "big") + pdu
                self.transport._send_to_network_layer(pdu, self.source_port, self.destination_port, True)
                self.ack_transmitted_at = time.time()
            time.sleep(to_sleep)
        with self.transport.big_lock:
            self.transport.stream_sockets.pop((self.source_port, self.destination_port))
            self.transport.recently_used_ports[self.source_port] = time.time()
