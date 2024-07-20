from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import os

class KeyManager:
    """
    KeyManager class for managing encryption keys.

    Attributes:
        private_key: The RSA private key.
        public_key: The RSA public key.
        symmetric_key: The symmetric key (AES key).

    Methods:
        generate_rsa_key_pair: Generates an RSA key pair (private and public keys).
        export_rsa_public_key: Exports the RSA public key to a file.
        import_rsa_public_key: Imports the RSA public key from a file.
        encrypt_symmetric_key: Encrypts the symmetric key using the RSA public key.
        decrypt_symmetric_key: Decrypts the encrypted symmetric key using the RSA private key.
        get_symmetric_key: Returns the symmetric key.
        generate_symmetric_key: Generates a random symmetric key (AES key).
        export_symmetric_key: Exports the symmetric key to a file.
        import_symmetric_key: Imports the symmetric key from a file.
    """

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.symmetric_key = None

    def generate_rsa_key_pair(self):
        """
        Generates an RSA key pair (private and public keys).
        """
        # Generate RSA key pair (private and public keys)
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,  # Commonly used public exponent
            key_size=2048,  # Key size
            backend=default_backend()  # Backend
        )
        self.public_key = self.private_key.public_key()  # Extract RSA public key

    def export_rsa_public_key(self, path):
        """
        Exports the RSA public key to a file.

        Args:
            path: The path to the file where the public key will be exported.
        """
        # Export RSA public key to a file
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,  # Encoding type
            format=serialization.PublicFormat.SubjectPublicKeyInfo  # Public key format
        )
        with open(path, 'wb') as f:  # Write the public key to a file
            f.write(pem)

    def import_rsa_public_key(self, path):
        """
        Imports the RSA public key from a file.

        Args:
            path: The path to the file containing the public key.
        """
        # Import RSA public key from a file
        with open(path, 'rb') as f:  # Read the public key from a file
            pem_data = f.read()
            self.public_key = serialization.load_pem_public_key(
                pem_data,  # Public key data
                backend=default_backend()  # Backend
            )

    def encrypt_symmetric_key(self, symmetric_key):
        """
        Encrypts the symmetric key using the RSA public key.

        Args:
            symmetric_key: The symmetric key to be encrypted.

        Returns:
            The encrypted symmetric key.
        """
        # Encrypt symmetric key using RSA public key
        encrypted_key = self.public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    def decrypt_symmetric_key(self, encrypted_key):
        """
        Decrypts the encrypted symmetric key using the RSA private key.

        Args:
            encrypted_key: The encrypted symmetric key to be decrypted.

        Returns:
            The decrypted symmetric key.
        """
        # Decrypt symmetric key using RSA private key
        decrypted_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.symmetric_key = decrypted_key
        return decrypted_key

    def get_symmetric_key(self):
        """
        Returns the symmetric key.

        Returns:
            The symmetric key.
        """
        return self.symmetric_key

    def generate_symmetric_key(self):
        """
        Generates a random symmetric key (AES key).
        """
        # Generate a random symmetric key (AES key)
        self.symmetric_key = os.urandom(32)  # 256-bit key for AES

    def export_symmetric_key(self, path):
        """
        Exports the symmetric key to a file.

        Args:
            path: The path to the file where the symmetric key will be exported.
        """
        # Export symmetric key to a file
        with open(path, 'wb') as f:
            f.write(self.symmetric_key)

    def import_symmetric_key(self, path):
        """
        Imports the symmetric key from a file.

        Args:
            path: The path to the file containing the symmetric key.
        """
        # Import symmetric key from a file
        with open(path, 'rb') as f:
            self.symmetric_key = f.read()
