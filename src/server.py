import socket
from AESCipher import AESCipher  
from KeyManager import KeyManager  

def start_server(host, port):
    key_manager = KeyManager()
    key_manager.generate_rsa_key_pair()
    key_manager.export_rsa_public_key('rsa_public_key.pem')
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
                    with open('rsa_public_key.pem', 'rb') as f:
                        rsa_public_key = f.read()
                    conn.sendall(rsa_public_key)

                    encrypted_symmetric_key = conn.recv(4096)
                    key_manager.import_rsa_public_key('rsa_public_key.pem')
                    symmetric_key = key_manager.decrypt_symmetric_key(encrypted_symmetric_key)

                    aes_cipher = AESCipher(symmetric_key)

                    encrypted_data = conn.recv(4096)
                    if encrypted_data:
                        decrypted_data = aes_cipher.decrypt(encrypted_data)
                        print(f"Decrypted data from client: {decrypted_data.decode()}")
                except Exception as e:
                    print(f"An error occurred: {e}")

if __name__ == "__main__":
    HOST = 'localhost'
    PORT = 12345
    start_server(HOST, PORT)
