# protoflow/parser/packet_parser.py

from typing import Tuple, List
from protoflow.utils.helpers import decode_varint


def parse_buffer(
    buffer: bytes, prefix: bytes
) -> Tuple[List[Tuple[str, int, bytes]], bytes]:
    """
    Analyse un buffer continu de paquets et extrait les messages complets.

    Chaque message est représenté par un tuple contenant :
      - le code type (les trois lettres, str),
      - la taille du message (int),
      - le contenu encodé du message (bytes).

    Le format du message attendu est :
      prefix + code (3 octets) + taille (varint) + message_data (taille octets)

    :param buffer: Buffer continu contenant des données brutes.
    :param prefix: Préfixe à rechercher dans le buffer.
    :return: Un tuple composé de la liste des messages extraits et du reste du buffer non traité.
    """
    messages: List[Tuple[str, int, bytes]] = []
    prefix_length = len(prefix)

    while True:
        # Recherche du préfixe dans le buffer
        index = buffer.find(prefix)
        if index == -1:
            return messages, buffer

        # On élimine les données avant le préfixe
        buffer = buffer[index:]

        # Vérifier qu'il y a assez de données pour le préfixe et le code
        if len(buffer) < prefix_length + 3:
            return messages, buffer

        # Extraction du code (3 octets) après le préfixe
        code_bytes = buffer[prefix_length : prefix_length + 3]
        try:
            code = code_bytes.decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("Code de type non décodable en ASCII")

        # Décodage du varint pour la taille du message
        varint_start = prefix_length + 3
        try:
            message_length, varint_length = decode_varint(buffer[varint_start:])
        except ValueError:
            # Varint incomplet, on attend plus de données.
            return messages, buffer

        total_header_length = prefix_length + 3 + varint_length
        total_message_length = total_header_length + message_length

        if len(buffer) < total_message_length:
            # Message incomplet, on retourne le buffer pour attendre plus de données.
            return messages, buffer

        # Extraction du contenu du message
        message_data = buffer[total_header_length:total_message_length]
        messages.append((code, message_length, message_data))

        # Retirer le message traité du buffer et continuer l'analyse
        buffer = buffer[total_message_length:]
