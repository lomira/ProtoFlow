import threading
import time
from typing import Optional
from scapy.all import sniff, TCP, AsyncSniffer
from protoflow.parser.packet_parser import parse_buffer


class PacketBuffer:
    """
    Buffer thread-safe pour accumuler les payloads TCP.
    """

    def __init__(self):
        self.buffer = b""
        self.lock = threading.Lock()

    def add(self, data: bytes) -> None:
        with self.lock:
            self.buffer += data

    def get(self) -> bytes:
        with self.lock:
            return self.buffer

    def set(self, new_buffer: bytes) -> None:
        with self.lock:
            self.buffer = new_buffer


def start_async_sniffer(
    buffer_obj: PacketBuffer, port: int = 5555, interface: Optional[str] = None
) -> AsyncSniffer:
    """
    Lance un AsyncSniffer qui ajoute les payloads TCP au buffer partagé.
    """
    bpf_filter = f"tcp port {port}"

    def packet_callback(pkt):
        if pkt.haslayer(TCP):
            tcp_payload = bytes(pkt[TCP].payload)
            if tcp_payload:
                buffer_obj.add(tcp_payload)

    sniffer = AsyncSniffer(
        filter=bpf_filter, iface=interface, prn=packet_callback, store=False
    )
    sniffer.start()
    return sniffer


def sniff_for_message(
    prefix: bytes,
    port: int = 5555,
    interface: Optional[str] = None,
    check_interval: float = 0.1,
    global_timeout: Optional[int] = None,
) -> bytes:
    """
    Utilise AsyncSniffer pour capturer en continu les paquets TCP sur le port spécifié et
    accumuler leur payload dans un buffer partagé. La fonction vérifie régulièrement ce buffer
    à l'aide de parse_buffer et renvoie dès qu'un message complet est détecté.

    :param prefix: Préfixe du message (incluant le code à 3 lettres et l'octet supplémentaire).
    :param port: Port d'écoute (5555 par défaut).
    :param interface: Interface réseau à utiliser (optionnel).
    :param check_interval: Intervalle (en secondes) entre chaque vérification du buffer.
    :param global_timeout: Timeout global en secondes (optionnel). Si None, la fonction attend indéfiniment.
    :return: Le contenu du message complet (message_data) en bytes.
    :raises TimeoutError: Si un timeout global est défini et est atteint.
    """
    buffer_obj = PacketBuffer()
    sniffer = start_async_sniffer(buffer_obj, port, interface)
    start_time = time.time()

    try:
        while True:
            current_buffer = buffer_obj.get()
            messages, remaining = parse_buffer(current_buffer, prefix)
            if messages:
                # On met à jour le buffer avec les données restantes
                buffer_obj.set(remaining)
                return messages[0]
            if (
                global_timeout is not None
                and (time.time() - start_time) > global_timeout
            ):
                raise TimeoutError(
                    "Global timeout reached while waiting for complete message."
                )
            time.sleep(check_interval)
    finally:
        sniffer.stop()
