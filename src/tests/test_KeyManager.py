import os
import unittest
from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from src.KeyManager import KeyManager

class KeyManagerTests(unittest.TestCase):
    def setUp(self):
        self.key_manager = KeyManager()

    def test_generate_rsa_key_pair(self):
        self.key_manager.generate_rsa_key_pair()
        self.assertIsNotNone(self.key_manager.private_key)
        self.assertIsNotNone(self.key_manager.public_key)

    def test_export_import_rsa_public_key(self):
        self.key_manager.generate_rsa_key_pair()
        self.key_manager.export_rsa_public_key("public_key.pem")
        self.key_manager.import_rsa_public_key("public_key.pem")
        self.assertIsNotNone(self.key_manager.public_key)

    def test_encrypt_decrypt_symmetric_key(self):
        self.key_manager.generate_rsa_key_pair()
        self.key_manager.generate_symmetric_key()
        symmetric_key = self.key_manager.get_symmetric_key()
        encrypted_key = self.key_manager.encrypt_symmetric_key(symmetric_key)
        decrypted_key = self.key_manager.decrypt_symmetric_key(encrypted_key)
        self.assertEqual(decrypted_key, symmetric_key)

    def test_generate_symmetric_key(self):
        self.key_manager.generate_symmetric_key()
        self.assertIsNotNone(self.key_manager.symmetric_key)

    def test_export_import_symmetric_key(self):
        self.key_manager.generate_symmetric_key()
        self.key_manager.export_symmetric_key("symmetric_key.bin")
        self.key_manager.import_symmetric_key("symmetric_key.bin")
        self.assertIsNotNone(self.key_manager.symmetric_key)

if __name__ == "__main__":
    unittest.main()