# protoflow/parser/packet_parser.py

from typing import Tuple, List
from protoflow.utils.helpers import decode_varint


def parse_buffer(buffer: bytes, prefix: bytes) -> Tuple[List[bytes], bytes]:
    """
    Analyse un buffer continu de paquets et extrait les messages complets.

    Chaque message est représenté par le contenu du message encodé (bytes).

    Le format du message attendu est :
      prefix + taille (varint) + message_data (taille octets)

    :param buffer: Buffer continu contenant des données brutes.
    :param prefix: Préfixe à rechercher dans le buffer. Ce préfixe inclut déjà le code de type.
    :return: Un tuple composé de la liste des message_data extraits et du reste du buffer non traité.
    """
    messages: List[bytes] = []
    prefix_length = len(prefix)

    while True:
        # Recherche du préfixe dans le buffer
        index = buffer.find(prefix)
        if index == -1:
            return messages, buffer

        # On élimine les données précédant le préfixe
        buffer = buffer[index:]

        # Vérifier qu'on a au moins le préfixe
        if len(buffer) < prefix_length:
            return messages, buffer

        # Décodage du varint pour la taille du message, juste après le préfixe
        varint_start = prefix_length + 1
        try:
            message_length, varint_length = decode_varint(buffer[varint_start:])
            print(message_length)
        except ValueError:
            # Varint incomplet, on attend plus de données.
            return messages, buffer

        total_header_length = prefix_length + varint_length
        total_message_length = total_header_length + message_length

        if len(buffer) < total_message_length:
            # Message incomplet, on retourne le buffer pour attendre plus de données.
            return messages, buffer

        # Extraction du contenu du message
        message_data = buffer[total_header_length:total_message_length]
        messages.append(message_data)

        # Retirer le message traité du buffer et continuer l'analyse
        buffer = buffer[total_message_length:]
