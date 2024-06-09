import logging
from typing import cast
import zlib
import time

from dns.tunnel.interfaces import NetworkLayerInterface, TransportLayerInterface, LinkLayerInterface

# Fragment layout:
# 4 bytes: CRC32 of the following:
# 2 bytes: fragment ID
# 2 bytes: fragment index
# 2 bytes: total fragments
# variable: fragment data

# Reassembled layout:
# 4 bytes: CRC32 of the following:
# variable: transport PDU

FRAGMENT_HEADER_SIZE = 10

def fragment_transport_pdu(pdu: bytes, mtu: int, fragment_id: int) -> list[bytes]:
    assert 0 <= fragment_id < 65536
    assert FRAGMENT_HEADER_SIZE < mtu
    fragments = []
    pdu = zlib.crc32(pdu).to_bytes(4, "big") + pdu
    index = 0
    data_per_fragment = mtu - FRAGMENT_HEADER_SIZE
    total_fragments = (len(pdu) + data_per_fragment - 1) // data_per_fragment
    for index in range(total_fragments):
        offset = index * data_per_fragment
        fragment_data = pdu[offset:offset + data_per_fragment]
        fragment = fragment_id.to_bytes(2, "big") + index.to_bytes(2, "big") + total_fragments.to_bytes(2, "big") + fragment_data
        fragment = zlib.crc32(fragment).to_bytes(4, "big") + fragment
        fragments.append(fragment)
    return fragments

class ReassemblyBucket:
    total_frags: int
    remaining_frags: int
    created_at: float
    fragments: list[bytes | None]
    def __init__(self, total_frags: int):
        self.total_frags = total_frags
        self.remaining_frags = total_frags
        self.fragments = [None] * total_frags
        self.created_at = time.time()
#TODO make thread safe!!!!!! add deques, don't do any processing in the direct interface calls
class NetworkLayer(NetworkLayerInterface):
    transport: TransportLayerInterface | None = None
    link: LinkLayerInterface | None = None
    link_send_mtu: int
    reassembly_buffer: dict[int, ReassemblyBucket]
    last_sent_fragment_id: int

    def _process_fragment(self, fragment: bytes):
        crc32 = int.from_bytes(fragment[:4], "big")
        if crc32 != zlib.crc32(fragment[4:]):
            logging.warning("CRC32 mismatch in fragment")
            return
        try:
            frag_id = int.from_bytes(fragment[4:6], "big")
            frag_index = int.from_bytes(fragment[6:8], "big")
            total_frags = int.from_bytes(fragment[8:10], "big")
            fragment_data = fragment[10:]
        except IndexError:
            logging.warning("Fragment too short")
            return
        if frag_index >= total_frags:
            logging.warning("Fragment index greater than total fragments")
            return
        if frag_id not in self.reassembly_buffer:
            logging.info(f"New reassembly bucket for fragment ID {frag_id}, received index {frag_index}")
            self.reassembly_buffer[frag_id] = ReassemblyBucket(total_frags)
        bucket = self.reassembly_buffer[frag_id]
        if bucket.fragments[frag_index] is not None:
            logging.warning("Duplicate fragment")
            return
        if bucket.total_frags != total_frags:
            logging.warning("Total fragments mismatch")
            return
        bucket.fragments[frag_index] = fragment_data
        bucket.remaining_frags -= 1
        logging.info("Received fragment %d of %d for fragment ID %d, %d remaining", frag_index, total_frags, frag_id, bucket.remaining_frags)
        if bucket.remaining_frags == 0:
            logging.info("Reassembling PDU with fragment ID %d", frag_id)
            pdu = bytearray()
            for frag in cast(list[bytes], bucket.fragments):
                pdu += frag
            if zlib.crc32(pdu[4:]) != int.from_bytes(pdu[:4], "big"):
                logging.warning("CRC32 mismatch in reassembled PDU, data is %s", pdu[4:].hex())
                return
            if self.transport is not None:
                self.transport.receive_from_network_layer(pdu[4:])
            else:
                logging.warning("No transport layer interface registered")
            self.reassembly_buffer.pop(frag_id)

    def receive_from_link_layer(self, network_pdus: list[bytes]):
        logging.info(f"Network layer received {len(network_pdus)} PDUs")
        for pdu in network_pdus:
            self._process_fragment(pdu)

    def queue_transmission_from_transport_layer(self, transport_pdus: bytes):
        fragments = fragment_transport_pdu(transport_pdus, self.link_send_mtu, self.last_sent_fragment_id)
        self.last_sent_fragment_id = (self.last_sent_fragment_id + 1) % 65536
        if self.link is not None:
            self.link.queue_transmission_from_network_layer(fragments)
        else:
            logging.warning("No link layer interface registered")

    def register_link_interface(self, interface: LinkLayerInterface):
        self.link = interface

    def register_transport_interface(self, interface: TransportLayerInterface):
        self.transport = interface

    def __init__(self, link_send_mtu: int):
        self.link_send_mtu = link_send_mtu
        self.reassembly_buffer = {}
        self.last_sent_fragment_id = 0
