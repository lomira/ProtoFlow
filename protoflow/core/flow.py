from typing import Optional
from protoflow.core.sniffer import sniff_for_message
from protoflow.core.reader import read_message_from_pcap_file


def get_message(
    prefix: bytes,
    file_path: Optional[str] = None,
    port: int = 5555,
    interface: Optional[str] = None,
    check_interval: Optional[float] = 0.1,
    timeout: Optional[int] = None,
) -> bytes:
    """
    Récupère un message complet en utilisant une source uniforme, qui est le fichier si file_path existe
    sinon sniff le port

    :param prefix: Préfixe attendu (incluant le code à 3 lettres et l'octet supplémentaire).
    :param file_path: Chemin vers le fichier pcap (obligatoire si source == 'file').
    :param port: Port à écouter pour le sniffing (par défaut 5555).
    :param interface: Interface réseau à utiliser pour le sniffing.
    :param timeout: Timeout pour la capture d'un paquet (optionnel).
    :return: Le contenu du message complet (message_data) en bytes.
    """
    if file_path is None:
        return sniff_for_message(prefix, port, interface, check_interval, timeout)
    else:
        return read_message_from_pcap_file(file_path, prefix)
