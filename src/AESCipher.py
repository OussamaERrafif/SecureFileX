from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os

class AESCipher:
    """
    AESCipher class provides methods for encrypting and decrypting data using AES CBC mode.

    Args:
        key (bytes): The AES encryption key.

    Attributes:
        key (bytes): The AES encryption key.

    Methods:
        encrypt(plaintext): Encrypts the given plaintext using AES CBC mode.
        decrypt(encrypted_data): Decrypts the given encrypted data using AES CBC mode.
    """

    def __init__(self, key):
        self.key = key

    def encrypt(self, plaintext):
        """
        Encrypts the given plaintext using AES CBC mode.

        Args:
            plaintext (bytes): The data to be encrypted.

        Returns:
            bytes: The encrypted data.

        Raises:
            None
        """
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        encrypted_data = iv + ciphertext
        return encrypted_data

    def decrypt(self, encrypted_data):
        """
        Decrypts the given encrypted data using AES-CBC mode.

        Args:
            encrypted_data (bytes): The encrypted data to be decrypted.

        Returns:
            bytes: The decrypted plaintext.

        Raises:
            ValueError: If the encrypted data is invalid or cannot be decrypted.
        """
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext
