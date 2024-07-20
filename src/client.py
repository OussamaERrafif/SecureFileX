import socket
import sys
from AESCipher import AESCipher  
from KeyManager import KeyManager  

def start_client(host, port, buffer_data):
    key_manager = KeyManager()

    # Load server's RSA public key for key exchange
    key_manager.import_rsa_public_key('rsa_public_key.pem')

    # Generate or load AES key for symmetric encryption
    key_manager.generate_symmetric_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Connected to server at {host}:{port}")

        try:
            # Receive RSA public key from server
            rsa_public_key = client_socket.recv(4096)  # Increased buffer size

            # Send RSA-encrypted AES key to server
            encrypted_symmetric_key = key_manager.encrypt_symmetric_key(key_manager.get_symmetric_key())
            client_socket.sendall(encrypted_symmetric_key)

            # Initialize AESCipher with symmetric key
            aes_cipher = AESCipher(key_manager.get_symmetric_key())

            # Encrypt and send data to server
            encrypted_data = aes_cipher.encrypt(buffer_data)
            client_socket.sendall(encrypted_data)
            print(f"Sent encrypted data to server: {buffer_data.decode()}")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python client.py <buffer_data>")
        sys.exit(1)
    
    HOST = 'localhost'  # Server's IP address or hostname
    PORT = 12345  # Server's port number
    buffer_data = sys.argv[1].encode()  # Data to send to server

    start_client(HOST, PORT, buffer_data)
