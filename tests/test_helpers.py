import unittest
from protoflow.utils.helpers import decode_varint


class TestDecodeVarint(unittest.TestCase):
    def test_single_byte(self):
        # Test pour des valeurs encodées sur un seul octet.
        # 0 est encodé en b'\x00'
        value, length = decode_varint(b"\x00")
        self.assertEqual(value, 0)
        self.assertEqual(length, 1)

        # 1 est encodé en b'\x01'
        value, length = decode_varint(b"\x01")
        self.assertEqual(value, 1)
        self.assertEqual(length, 1)

        # 127 est encodé en b'\x7F'
        value, length = decode_varint(b"\x7F")
        self.assertEqual(value, 127)
        self.assertEqual(length, 1)

    def test_multi_byte(self):
        # Test pour des valeurs nécessitant plusieurs octets.
        # 128 doit être encodé en b'\x80\x01'
        value, length = decode_varint(b"\x80\x01")
        self.assertEqual(value, 128)
        self.assertEqual(length, 2)

        # 300 doit être encodé en b'\xAC\x02'
        value, length = decode_varint(b"\xAC\x02")
        self.assertEqual(value, 300)
        self.assertEqual(length, 2)

    def test_incomplete_varint(self):
        # Vérifier que l'absence de bytes suffisants déclenche une ValueError.
        with self.assertRaises(ValueError):
            decode_varint(
                b"\x80"
            )  # Varint incomplet : le bit de continuation est activé mais aucun byte suivant.

    def test_longer_varint(self):
        # Test avec un varint sur plusieurs octets.
        # Par exemple, 16384 (2**14) devrait être encodé en b'\x80\x80\x01'
        value, length = decode_varint(b"\x80\x80\x01")
        self.assertEqual(value, 16384)
        self.assertEqual(length, 3)


if __name__ == "__main__":
    unittest.main()
