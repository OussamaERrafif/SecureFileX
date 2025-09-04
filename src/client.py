import socket
import sys
from AESCipher import AESCipher  
from KeyManager import KeyManager  

def start_client(host, port):
    """
    Connects to a server at the specified host and port, and sends/receives encrypted messages.

    Args:
        host (str): The host address of the server.
        port (int): The port number of the server.

    Raises:
        Exception: If an error occurs during the communication with the server.

    Returns:
        None
    """
    key_manager = KeyManager()
    key_manager.import_rsa_public_key('rsa_public_key.pem')
    key_manager.generate_symmetric_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Connected to server at {host}:{port}")

        try:
            rsa_public_key = client_socket.recv(4096)
            encrypted_symmetric_key = key_manager.encrypt_symmetric_key(key_manager.get_symmetric_key())
            client_socket.sendall(encrypted_symmetric_key)

            aes_cipher = AESCipher(key_manager.get_symmetric_key())

            while True:
                message = input("Enter message to send to server (type 'quit' to exit): ")
                if message.lower() == 'quit':
                    break
                    
                buffer_data = message.encode()
                encrypted_data = aes_cipher.encrypt(buffer_data)
                client_socket.sendall(encrypted_data)
                print(f"Sent encrypted data to server: {message}")

                # Wait for response from server
                encrypted_response = client_socket.recv(4096)
                if encrypted_response:
                    decrypted_response = aes_cipher.decrypt(encrypted_response)
                    print(f"Server response: {decrypted_response.decode()}")
                else:
                    print("No response from server")
                    break

        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    HOST = 'localhost'
    PORT = 12345

    start_client(HOST, PORT)
