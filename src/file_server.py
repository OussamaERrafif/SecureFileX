import socket
import json
import os
from AESCipher import AESCipher  
from KeyManager import KeyManager
from FileHandler import FileHandler
from Authenticator import SimpleAuthenticator, AuthenticationMixin


class SecureFileTransferServer(AuthenticationMixin):
    """
    Secure file transfer server with encryption, authentication, and integrity verification.
    """
    
    def __init__(self, host='localhost', port=12345, upload_dir='uploads'):
        self.host = host
        self.port = port
        self.upload_dir = upload_dir
        self.key_manager = KeyManager()
        
        # Create upload directory if it doesn't exist
        os.makedirs(upload_dir, exist_ok=True)
        
        # Generate RSA key pair for secure key exchange
        self.key_manager.generate_rsa_key_pair()
        self.key_manager.export_rsa_public_key('rsa_public_key.pem')
    
    def start_server(self):
        """Start the file transfer server."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(1)
            print(f"File Transfer Server listening on {self.host}:{self.port}")
            print(f"Upload directory: {os.path.abspath(self.upload_dir)}")

            while True:
                conn, addr = server_socket.accept()
                with conn:
                    print(f"Connected by {addr}")
                    try:
                        self.handle_client(conn)
                    except Exception as e:
                        print(f"Error handling client {addr}: {e}")
    
    def handle_client(self, conn):
        """Handle a client connection with authentication."""
        # Send RSA public key to client
        with open('rsa_public_key.pem', 'rb') as f:
            rsa_public_key = f.read()
        conn.sendall(rsa_public_key)

        # Receive encrypted symmetric key from client
        encrypted_symmetric_key = conn.recv(4096)
        symmetric_key = self.key_manager.decrypt_symmetric_key(encrypted_symmetric_key)
        
        # Initialize AES cipher with the symmetric key
        aes_cipher = AESCipher(symmetric_key)
        
        # Require authentication
        auth_success, token, username = self.require_authentication(conn, aes_cipher)
        if not auth_success:
            print(f"Authentication failed for client")
            return
        
        print(f"User '{username}' authenticated successfully")
        
        while True:
            try:
                # Receive command from client
                encrypted_command = conn.recv(4096)
                if not encrypted_command:
                    break
                
                command_data = json.loads(aes_cipher.decrypt(encrypted_command).decode())
                command = command_data.get('command')
                user_token = command_data.get('token')
                
                # Validate token for each request
                token_valid, current_user, _ = self.validate_session(user_token)
                if not token_valid or current_user != username:
                    self.send_response(conn, aes_cipher, {
                        'status': 'error', 
                        'message': 'Invalid or expired session'
                    })
                    break
                
                if command == 'UPLOAD':
                    self.handle_file_upload(conn, aes_cipher, command_data, username)
                elif command == 'MESSAGE':
                    self.handle_message(conn, aes_cipher, command_data, username)
                elif command == 'QUIT':
                    self.authenticator.logout(user_token)
                    self.send_response(conn, aes_cipher, {'status': 'goodbye'})
                    break
                else:
                    self.send_response(conn, aes_cipher, {'status': 'error', 'message': 'Unknown command'})
                    
            except Exception as e:
                print(f"Error processing command: {e}")
                self.send_response(conn, aes_cipher, {'status': 'error', 'message': str(e)})
    
    def handle_file_upload(self, conn, aes_cipher, command_data, username):
        """Handle file upload from authenticated client."""
        filename = command_data.get('filename')
        file_size = command_data.get('file_size')
        expected_hash = command_data.get('file_hash')
        
        if not all([filename, file_size, expected_hash]):
            self.send_response(conn, aes_cipher, {'status': 'error', 'message': 'Missing file metadata'})
            return
        
        # Sanitize filename
        safe_filename = os.path.basename(filename)
        file_path = os.path.join(self.upload_dir, safe_filename)
        
        print(f"User '{username}' uploading file: {safe_filename} ({file_size} bytes)")
        
        # Send ready response
        self.send_response(conn, aes_cipher, {'status': 'ready'})
        
        # Receive file data in chunks
        received_chunks = []
        total_received = 0
        
        while total_received < file_size:
            encrypted_chunk = conn.recv(8192)
            if not encrypted_chunk:
                break
            
            decrypted_chunk = aes_cipher.decrypt(encrypted_chunk)
            received_chunks.append(decrypted_chunk)
            total_received += len(decrypted_chunk)
            
            # Send progress update
            progress = (total_received / file_size) * 100
            print(f"Upload progress: {progress:.1f}%")
        
        # Write file
        try:
            FileHandler.write_file_chunks(file_path, received_chunks)
            
            # Verify file integrity
            if FileHandler.verify_file_integrity(file_path, expected_hash):
                print(f"File {safe_filename} uploaded successfully and verified")
                self.send_response(conn, aes_cipher, {
                    'status': 'success', 
                    'message': f'File {safe_filename} uploaded and verified successfully'
                })
            else:
                os.remove(file_path)  # Remove corrupted file
                self.send_response(conn, aes_cipher, {
                    'status': 'error', 
                    'message': 'File integrity verification failed'
                })
                
        except Exception as e:
            self.send_response(conn, aes_cipher, {'status': 'error', 'message': f'File write error: {e}'})
    
    def handle_message(self, conn, aes_cipher, command_data, username):
        """Handle text message from authenticated client."""
        message = command_data.get('message', '')
        print(f"Message from user '{username}': {message}")
        self.send_response(conn, aes_cipher, {'status': 'success', 'message': 'Message received'})
    
    def send_response(self, conn, aes_cipher, response_data):
        """Send encrypted response to client."""
        response_json = json.dumps(response_data).encode()
        encrypted_response = aes_cipher.encrypt(response_json)
        conn.sendall(encrypted_response)


if __name__ == "__main__":
    server = SecureFileTransferServer()
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\nServer shutdown")
    except Exception as e:
        print(f"Server error: {e}")