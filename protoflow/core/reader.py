from typing import Iterator
from scapy.all import rdpcap


def read_pcap_file(filepath: str) -> Iterator[bytes]:
    """
    Lit un fichier pcap et renvoie un itérateur sur les paquets bruts.

    :param filepath: Chemin du fichier *.pcap.
    :return: Itérateur de paquets sous forme de bytes.
    """
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        raise e

    for packet in packets:
        # Convertit chaque paquet en bytes
        yield bytes(packet)
