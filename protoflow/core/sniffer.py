# protoflow/core/sniffer.py

from typing import Optional
from scapy.all import sniff, TCP
from protoflow.parser.packet_parser import parse_buffer


def sniff_for_message(
    prefix: bytes,
    port: int = 5555,
    interface: Optional[str] = None,
    timeout: Optional[int] = None,
) -> bytes:
    """
    Écoute sur le port spécifié et accumule les charges utiles TCP reçues jusqu'à obtenir
    un message complet correspondant au format :
      prefix (incluant le code à 3 lettres) + 1 octet supplémentaire + taille (varint) + message_data

    :param port: Port d'écoute (5555 par défaut).
    :param prefix: Préfixe à rechercher dans le flux (incluant déjà le code à 3 lettres).
    :param interface: Nom de l'interface réseau à utiliser (optionnel).
    :param timeout: Délai maximum (en secondes) pour l'écoute d'un paquet (optionnel).
    :return: Le contenu du message complet (message_data) sous forme de bytes.
    """
    buffer = b""
    bpf_filter = f"tcp port {port}"

    while True:
        packets = sniff(count=50, filter=bpf_filter, iface=interface, timeout=timeout)
        if not packets:
            continue

        for pkt in packets:
            if pkt.haslayer(TCP):
                tcp_payload = bytes(pkt[TCP].payload)
                if tcp_payload:
                    buffer += tcp_payload

        messages, buffer = parse_buffer(buffer, prefix)
        if messages:
            return messages[0]
