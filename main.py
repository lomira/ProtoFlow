from protoflow.core.reader import read_pcap_file
from protoflow.parser.packet_parser import parse_buffer


def test_parse_buffer_from_pcap(pcap_filepath: str) -> None:
    buffer = b""
    for packet in read_pcap_file(pcap_filepath):
        buffer += packet
        messages, buffer = parse_buffer(buffer)
        if messages:
            print("Messages extraits :", messages)
    if buffer:
        print("Données non traitées en fin de flux :", buffer)


print(read_pcap_file("sample.pcap"))
