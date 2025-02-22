from typing import Iterator
from scapy.all import rdpcap, TCP
from protoflow.parser.packet_parser import parse_buffer


def read_pcap_payloads(filepath: str, port: int = 5555) -> Iterator[bytes]:
    """
    Lit un fichier pcap et renvoie un itérateur sur les payloads TCP non vides
    filtrés par le port (source ou destination).
    """
    packets = rdpcap(filepath)
    for pkt in packets:
        if pkt.haslayer(TCP):
            # Filtrer uniquement les paquets dont le sport ou dport correspond au port spécifié
            if pkt[TCP].sport == port or pkt[TCP].dport == port:
                tcp_payload = bytes(pkt[TCP].payload)
                if tcp_payload:
                    yield tcp_payload


def read_message_from_pcap_file(
    filepath: str, prefix: bytes, port: int = 5555
) -> bytes:
    """
    Accumule les payloads TCP d'un fichier pcap dans un buffer continu et
    renvoie le premier message complet trouvé via parse_buffer.

    :param filepath: Chemin du fichier pcap.
    :param prefix: Préfixe à rechercher (incluant le code à 3 lettres et l'octet supplémentaire).
    :return: Le contenu du message complet (message_data) en bytes.
    :raises ValueError: Si aucun message complet n'est trouvé.
    """
    buffer = b"".join([m for m in read_pcap_payloads(filepath)])

    # Tenter d'extraire le message complet à partir du buffer accumulé
    messages, _ = parse_buffer(buffer, prefix)
    if messages:
        return messages[0]
    else:
        raise ValueError("Aucun message complet trouvé dans le fichier pcap")
