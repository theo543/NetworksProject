from __future__ import annotations

from collections import deque
from threading import Condition, Event, Lock
import logging
import time

from dns.tunnel.interfaces import TransportLayerInterface, NetworkLayerInterface, DatagramSocketInterface, StreamSocketInterface

# Transport layer 
# 2 bytes: source port
# 2 bytes: destination port
# 1 byte: protocol
# variable: datagram or stream data

# Stream layout:
# 4 bytes: sequence number
# 4 bytes: acknowledgement number
# ???

class TransportLayer(TransportLayerInterface):
    network: NetworkLayerInterface | None = None
    datagram_sockets: dict[int, DatagramSocket]
    stream_sockets: dict[tuple[int, int], StreamSocket]
    stream_listening_accepts: dict[int, tuple[Event, list[StreamSocket]]] # socket will be put in list when accepted
    recently_used_ports: dict[int, float]
    big_lock: Lock

    def __init__(self):
        self.datagram_sockets = {}
        self.stream_sockets = {}
        self.stream_listening_accepts = {}
        self.recently_used_ports = {}
        self.big_lock = Lock()

    def _find_ephemeral_port(self) -> int:
        for port in range(0b1000000000000000, 0b1111111111111111):
            if port not in self.recently_used_ports and port not in self.datagram_sockets:
                return port
        raise ValueError("No free ephemeral ports")

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
                if (source_port, destination_port) in self.stream_sockets:
                    sock = self.stream_sockets[(source_port, destination_port)]
                    with sock.received_bytes_cv:
                        sock.received_pdus.append(pdu)
                        sock.received_bytes_cv.notify_all()
                elif destination_port in self.stream_listening_accepts:
                    (event, box) = self.stream_listening_accepts[destination_port]
                    box.append(StreamSocket._init_from_accept(source_port, destination_port, self))
                    self.stream_listening_accepts.pop(destination_port)
                    event.set()
                else:
                    logging.warning("No socket listening on destination stream port")
            else:
                if destination_port in self.datagram_sockets:
                    logging.info("PDU is datagram for socket on port %d", destination_port)
                    sock = self.datagram_sockets[destination_port]
                    with sock.received_datagrams_cv:
                        sock.received_datagrams.append((source_port, pdu))
                        sock.received_datagrams_cv.notify_all()
                else:
                    logging.warning("No socket listening on destination datagram port")

    def accept_stream_connection(self, listen_port: int) -> StreamSocket:
        with self.big_lock:
            if listen_port in self.stream_listening_accepts:
                raise ValueError("Already listening on port")
            event = Event()
            box: list[StreamSocket] = []
            self.stream_listening_accepts[listen_port] = (event, box)
        event.wait()
        return box.pop()

    def connect_stream(self, destination_port: int) -> StreamSocket:
        with self.big_lock:
            if destination_port in self.stream_sockets:
                raise ValueError("Already connected to port")
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

class StreamSocket(StreamSocketInterface):
    transport: TransportLayer
    source_port: int
    destination_port: int
    received_bytes_lock: Lock
    received_bytes_cv: Condition
    received_bytes: bytearray
    pending_transmission_lock: Lock
    pending_transmission_cv: Condition
    pending_transmission: bytearray
    pending_transmission_starting_sequence_number: int = 0
    received_pdus: deque[bytes]

    def __init__(self, transport: TransportLayer, source_port: int, destination_port):
        self.transport = transport
        self.received_bytes = bytearray()
        self.pending_transmission = bytearray()
        self.received_pdus = deque()
        self.received_bytes_lock = Lock()
        self.received_bytes_cv = Condition(self.received_bytes_lock)
        self.pending_transmission_lock = Lock()
        self.pending_transmission_cv = Condition(self.pending_transmission_lock)

    @classmethod
    def _init_from_accept(cls, source_port: int, destination_port: int, transport: TransportLayer) -> StreamSocket:
        self = StreamSocket(transport, source_port, destination_port)
        return self

    @classmethod
    def _init_as_client(cls, source_port: int, destination_port: int, transport: TransportLayer) -> StreamSocket:
        self = StreamSocket(transport, source_port, destination_port)
        return self

    def pop_data(self) -> bytes:
        def data_available():
            with self.received_bytes_lock:
                return len(self.received_bytes) != 0
        with self.received_bytes_cv:
            self.received_bytes_cv.wait_for(data_available)
            data = self.received_bytes
            self.received_bytes = bytearray()
        return data

    def close(self):
        with self.transport.big_lock:
            self.transport.stream_sockets.pop((self.source_port, self.destination_port))
            self.transport.recently_used_ports[self.source_port] = time.time()
        raise NotImplementedError()
