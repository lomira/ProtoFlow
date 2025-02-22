from typing import Tuple


def decode_varint(data: bytes) -> Tuple[int, int]:
    """
    Décode un varint depuis le buffer et retourne un tuple (valeur, nombre d'octets lus).

    :param data: Buffer contenant le varint.
    :return: Tuple (valeur, longueur du varint en octets).
    :raises ValueError: Si le varint est incomplet.
    """
    value = 0
    shift = 0
    for i, byte in enumerate(data):
        value |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return value, i + 1
        shift += 7
    raise ValueError("Varint incomplet, buffer terminé prématurément")
