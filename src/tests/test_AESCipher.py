import os
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from AESCipher import AESCipher

class AESCipherTests(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = os.urandom(32)  # Generate a random key
        cipher = AESCipher(key)

        plaintext = b"Hello, World!"
        encrypted_data = cipher.encrypt(plaintext)
        decrypted_plaintext = cipher.decrypt(encrypted_data)

        self.assertEqual(decrypted_plaintext, plaintext)

    def test_encrypt_decrypt_empty(self):
        key = os.urandom(32)  # Generate a random key
        cipher = AESCipher(key)

        plaintext = b""
        encrypted_data = cipher.encrypt(plaintext)
        decrypted_plaintext = cipher.decrypt(encrypted_data)

        self.assertEqual(decrypted_plaintext, plaintext)

    def test_encrypt_decrypt_long(self):
        key = os.urandom(32)  # Generate a random key
        cipher = AESCipher(key)

        plaintext = b"This is a long plaintext that is longer than 16 bytes."
        encrypted_data = cipher.encrypt(plaintext)
        decrypted_plaintext = cipher.decrypt(encrypted_data)

        self.assertEqual(decrypted_plaintext, plaintext)

if __name__ == "__main__":
    unittest.main()