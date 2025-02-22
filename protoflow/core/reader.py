from typing import Iterator
from scapy.all import rdpcap, TCP
from protoflow.parser.packet_parser import parse_buffer


def read_pcap_payloads(filepath: str) -> Iterator[bytes]:
    """
    Lit un fichier pcap et renvoie un itérateur sur les payloads TCP non vides.
    """
    packets = rdpcap(filepath)
    for pkt in packets:
        if pkt.haslayer(TCP):
            tcp_payload = bytes(pkt[TCP].payload)
            if tcp_payload:
                yield tcp_payload


def read_message_from_pcap_file(filepath: str, prefix: bytes) -> bytes:
    """
    Accumule les payloads TCP d'un fichier pcap dans un buffer continu et
    renvoie le premier message complet trouvé via parse_buffer.

    :param filepath: Chemin du fichier pcap.
    :param prefix: Préfixe à rechercher (incluant le code à 3 lettres et l'octet supplémentaire).
    :return: Le contenu du message complet (message_data) en bytes.
    :raises ValueError: Si aucun message complet n'est trouvé.
    """
    buffer = b""
    for payload in read_pcap_payloads(filepath):
        buffer += payload
        messages, buffer = parse_buffer(buffer, prefix)
        if messages:
            return messages[0]
    raise ValueError("Aucun message complet trouvé dans le fichier pcap")
