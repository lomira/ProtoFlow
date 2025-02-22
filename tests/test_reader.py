# tests/test_reader.py

import os
import unittest
from protoflow.core.reader import read_pcap_file


class TestReadPcapFile(unittest.TestCase):
    def test_read_pcap_file(self):
        # Chemin vers le fichier pcap de test
        pcap_filepath = "sample.pcap"

        # Vérifier que le fichier pcap existe
        self.assertTrue(
            os.path.exists(pcap_filepath),
            f"Le fichier pcap n'existe pas : {pcap_filepath}",
        )

        # Lire les paquets du fichier
        packets = list(read_pcap_file(pcap_filepath))

        # S'assurer que l'on a lu au moins un paquet
        self.assertGreater(
            len(packets), 0, "Aucun paquet n'a été lu dans le fichier pcap"
        )

        # Vérifier que chaque paquet est de type bytes
        for packet in packets:
            self.assertIsInstance(
                packet, bytes, "Chaque paquet doit être de type bytes"
            )


if __name__ == "__main__":
    unittest.main()
