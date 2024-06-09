from __future__ import annotations

from enum import Enum
from ..packet import DNSPacket, DNSResourceRecord, DomainName, ResponseCode
from abc import ABC, abstractmethod

class LinkLayerInterface(ABC):
    @abstractmethod
    def queue_transmission_from_network_layer(self, network_pdus: list[bytes]):
        pass
    @abstractmethod
    def register_network_interface(self, interface: NetworkLayerInterface):
        pass

class NetworkLayerInterface(ABC):
    @abstractmethod
    def receive_from_link_layer(self, network_pdus: list[bytes]):
        pass
    @abstractmethod
    def queue_transmission_from_transport_layer(self, transport_pdus: bytes):
        pass
    @abstractmethod
    def register_transport_interface(self, interface: TransportLayerInterface):
        pass
    @abstractmethod
    def register_link_interface(self, interface: LinkLayerInterface):
        pass

class TransportLayerInterface(ABC):
    @abstractmethod
    def register_network_interface(self, interface: NetworkLayerInterface):
        pass
    @abstractmethod
    def receive_from_network_layer(self, transport_pdu: bytes):
        pass
    @abstractmethod
    def accept_stream_connection(self, listen_port: int) -> StreamSocketInterface:
        pass
    @abstractmethod
    def connect_stream(self, destination_port: int) -> StreamSocketInterface:
        pass
    @abstractmethod
    def create_datagram_socket(self, source_port: int) -> DatagramSocketInterface:
        pass

class TransportLayerSocket(ABC):
    @abstractmethod
    def close(self):
        pass

class DatagramSocketInterface(TransportLayerSocket):
    @abstractmethod
    def pop_data(self) -> tuple[int, bytes]:
        pass
    def push_data(self, data: bytes, destination_port: int):
        pass

class StreamSocketInterface(TransportLayerSocket):
    @abstractmethod
    def pop_data(self, amount: int) -> bytes:
        pass
    def push_data(self, data: bytes):
        pass
