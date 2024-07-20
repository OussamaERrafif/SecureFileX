import socket
from AESCipher import AESCipher  # Assuming AESCipher class is defined in AESCipher.py
from KeyManager import KeyManager  # Assuming KeyManager class is defined in KeyManager.py

def start_server(host, port):
    key_manager = KeyManager()
    key_manager.generate_rsa_key_pair()  # Generate RSA key pair for key exchange

    # Export RSA public key for key exchange
    key_manager.export_rsa_public_key('rsa_public_key.pem')

    # Generate or load AES key for symmetric encryption
    key_manager.generate_symmetric_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(1)
        print(f"Server listening on {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"Connected by {addr}")

                try:
                    # Send RSA public key to client for key exchange
                    with open('rsa_public_key.pem', 'rb') as f:
                        rsa_public_key = f.read()
                    conn.sendall(rsa_public_key)

                    # Receive AES key encrypted with RSA public key from client
                    encrypted_symmetric_key = conn.recv(4096)  # Increased buffer size
                    key_manager.import_rsa_public_key('rsa_public_key.pem')
                    symmetric_key = key_manager.decrypt_symmetric_key(encrypted_symmetric_key)

                    # Initialize AESCipher with decrypted symmetric key
                    aes_cipher = AESCipher(symmetric_key)

                    # Receive encrypted data from client
                    encrypted_data = conn.recv(4096)  # Increased buffer size
                    if encrypted_data:
                        # Decrypt data using AESCipher
                        decrypted_data = aes_cipher.decrypt(encrypted_data)
                        print(f"Decrypted data from client: {decrypted_data.decode()}")
                except Exception as e:
                    print(f"An error occurred: {e}")

if __name__ == "__main__":
    HOST = 'localhost'  # Use '0.0.0.0' to accept connections from any IP
    PORT = 12345  # Port number for communication
    start_server(HOST, PORT)
