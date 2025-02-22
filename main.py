from typing import Tuple, List, Optional, Iterator
import threading
import time
from scapy.all import TCP, AsyncSniffer, rdpcap


def decode_varint(data: bytes) -> Tuple[int, int]:
    """
    Décode un varint depuis le buffer et retourne un tuple (valeur, nombre d'octets lus).
    """
    value = 0
    shift = 0
    for i, byte in enumerate(data):
        value |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return value, i + 1
        shift += 7
    raise ValueError("Varint incomplet, buffer terminé prématurément")


def parse_buffer(buffer: bytes, prefix: bytes) -> Tuple[List[bytes], bytes]:
    """
    Analyse un buffer continu et extrait les messages complets.

    Le format attendu est :
      prefix + 1 octet supplémentaire + taille (varint) + message_data (taille octets)

    :param buffer: Buffer continu contenant les données brutes.
    :param prefix: Préfixe à rechercher dans le buffer (incluant le code à 3 lettres).
    :return: (liste de message_data extraits, reste du buffer non traité)
    """
    messages: List[bytes] = []
    prefix_length = len(prefix)

    while True:
        index = buffer.find(prefix)
        if index == -1:
            return messages, buffer

        buffer = buffer[index:]
        if len(buffer) < prefix_length:
            return messages, buffer

        # On saute l'octet supplémentaire après le préfixe
        varint_start = prefix_length + 1
        try:
            message_length, varint_length = decode_varint(buffer[varint_start:])
        except ValueError:
            return messages, buffer

        total_header_length = prefix_length + 1 + varint_length
        total_message_length = total_header_length + message_length

        if len(buffer) < total_message_length:
            return messages, buffer

        message_data = buffer[total_header_length:total_message_length]
        messages.append(message_data)
        buffer = buffer[total_message_length:]


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
    Capture en continu les paquets TCP sur le port spécifié via AsyncSniffer,
    accumule leur payload dans un buffer partagé et retourne dès qu'un message complet est détecté.
    """
    buffer_obj = PacketBuffer()
    sniffer = start_async_sniffer(buffer_obj, port, interface)
    start_time = time.time()

    try:
        while True:
            current_buffer = buffer_obj.get()
            messages, remaining = parse_buffer(current_buffer, prefix)
            if messages:
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


def read_pcap_payloads(filepath: str, port: int = 5555) -> Iterator[bytes]:
    """
    Lit un fichier pcap et renvoie un itérateur sur les payloads TCP non vides filtrés par port.
    """
    packets = rdpcap(filepath)
    for pkt in packets:
        if pkt.haslayer(TCP):
            if pkt[TCP].sport == port or pkt[TCP].dport == port:
                tcp_payload = bytes(pkt[TCP].payload)
                if tcp_payload:
                    yield tcp_payload


def read_message_from_pcap_file(
    filepath: str, prefix: bytes, port: int = 5555
) -> bytes:
    """
    Accumule les payloads TCP d'un fichier pcap filtrés par port dans un buffer continu,
    puis retourne le premier message complet trouvé via parse_buffer.
    """
    buffer = b"".join(read_pcap_payloads(filepath, port))
    messages, _ = parse_buffer(buffer, prefix)
    if messages:
        return messages[0]
    else:
        raise ValueError("Aucun message complet trouvé dans le fichier pcap")


def get_message(
    prefix: bytes,
    file_path: Optional[str] = None,
    port: int = 5555,
    interface: Optional[str] = None,
    check_interval: Optional[float] = 0.1,
    timeout: Optional[int] = None,
) -> bytes:
    """
    Récupère un message complet depuis un flux uniforme :
      - Si file_path est fourni, lit à partir du fichier pcap.
      - Sinon, capture en live via sniffing sur le port.
    """
    if file_path is None:
        return sniff_for_message(prefix, port, interface, check_interval, timeout)
    else:
        return read_message_from_pcap_file(file_path, prefix, port)
