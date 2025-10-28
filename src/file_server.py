import socket
import json
import os
from AESCipher import AESCipher  
from KeyManager import KeyManager
from FileHandler import FileHandler
from Authenticator import SimpleAuthenticator, AuthenticationMixin
from Logger import get_logger
from Config import get_config


class SecureFileTransferServer(AuthenticationMixin):
    """
    Secure file transfer server with encryption, authentication, and integrity verification.
    """
    
    def __init__(self, host=None, port=None, upload_dir=None):
        super().__init__()
        self.config = get_config()
        
        # Use provided parameters or fall back to config
        self.host = host or self.config.server_config.host
        self.port = port or self.config.server_config.port
        self.upload_dir = upload_dir or self.config.server_config.upload_dir
        
        self.key_manager = KeyManager()
        self.logger = get_logger('Server')
        
        # Create upload directory if it doesn't exist
        os.makedirs(self.upload_dir, exist_ok=True)
        
        # Generate RSA key pair for secure key exchange
        self.key_manager.generate_rsa_key_pair()
        self.key_manager.export_rsa_public_key('rsa_public_key.pem')
        
        self.logger.info(f"Server initialized - Upload dir: {os.path.abspath(self.upload_dir)}")
    
    def start_server(self):
        """Start the file transfer server."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(self.config.server_config.max_connections)
            
            self.logger.info(f"Server listening on {self.host}:{self.port}")
            self.logger.info(f"Max connections: {self.config.server_config.max_connections}")
            print(f"File Transfer Server listening on {self.host}:{self.port}")
            print(f"Upload directory: {os.path.abspath(self.upload_dir)}")

            while True:
                conn, addr = server_socket.accept()
                client_ip = addr[0]
                self.logger.connection_event('CONNECT', client_ip)
                
                with conn:
                    print(f"Connected by {addr}")
                    try:
                        self.handle_client(conn, client_ip)
                    except Exception as e:
                        self.logger.error(f"Error handling client {addr}: {e}")
                        print(f"Error handling client {addr}: {e}")
                    finally:
                        self.logger.connection_event('DISCONNECT', client_ip)
    
    def handle_client(self, conn, client_ip):
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
            self.logger.security_event('AUTH_FAILED', 'Authentication failed', 
                                     username=username, ip_address=client_ip)
            return
        
        self.logger.security_event('AUTH_SUCCESS', 'User authenticated', 
                                 username=username, ip_address=client_ip)
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
                    self.logger.security_event('TOKEN_INVALID', 'Invalid or expired session',
                                             username=username, ip_address=client_ip)
                    self.send_response(conn, aes_cipher, {
                        'status': 'error', 
                        'message': 'Invalid or expired session'
                    })
                    break
                
                if command == 'UPLOAD':
                    self.handle_file_upload(conn, aes_cipher, command_data, username, client_ip)
                elif command == 'MESSAGE':
                    self.handle_message(conn, aes_cipher, command_data, username, client_ip)
                elif command == 'QUIT':
                    self.authenticator.logout(user_token)
                    self.logger.info(f"User '{username}' logged out")
                    self.send_response(conn, aes_cipher, {'status': 'goodbye'})
                    break
                else:
                    self.logger.warning(f"Unknown command '{command}' from user '{username}'")
                    self.send_response(conn, aes_cipher, {'status': 'error', 'message': 'Unknown command'})
                    
            except Exception as e:
                self.logger.error(f"Error processing command from {username}: {e}")
                self.send_response(conn, aes_cipher, {'status': 'error', 'message': str(e)})
    
    def handle_file_upload(self, conn, aes_cipher, command_data, username, client_ip):
        """Handle file upload from authenticated client."""
        filename = command_data.get('filename')
        file_size = command_data.get('file_size')
        expected_hash = command_data.get('file_hash')
        
        if not all([filename, file_size, expected_hash]):
            self.logger.warning(f"Upload failed: missing metadata from {username}")
            self.send_response(conn, aes_cipher, {'status': 'error', 'message': 'Missing file metadata'})
            return
        
        # Check file size limit
        if file_size > self.config.server_config.max_file_size:
            self.logger.warning(f"Upload rejected: file too large ({file_size} bytes) from {username}")
            self.send_response(conn, aes_cipher, {
                'status': 'error', 
                'message': f'File too large. Max size: {self.config.server_config.max_file_size} bytes'
            })
            return
        
        # Sanitize filename
        safe_filename = os.path.basename(filename)
        file_path = os.path.join(self.upload_dir, safe_filename)
        
        self.logger.info(f"User '{username}' uploading file: {safe_filename} ({file_size} bytes)")
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
                self.logger.file_operation('UPLOAD', safe_filename, username, True, file_size)
                print(f"File {safe_filename} uploaded successfully and verified")
                self.send_response(conn, aes_cipher, {
                    'status': 'success', 
                    'message': f'File {safe_filename} uploaded and verified successfully'
                })
            else:
                os.remove(file_path)  # Remove corrupted file
                self.logger.file_operation('UPLOAD', safe_filename, username, False, file_size)
                self.logger.warning(f"File integrity verification failed for {safe_filename}")
                self.send_response(conn, aes_cipher, {
                    'status': 'error', 
                    'message': 'File integrity verification failed'
                })
                
        except Exception as e:
            self.logger.file_operation('UPLOAD', safe_filename, username, False, file_size)
            self.logger.error(f"File write error for {safe_filename}: {e}")
            self.send_response(conn, aes_cipher, {'status': 'error', 'message': f'File write error: {e}'})
    
    def handle_message(self, conn, aes_cipher, command_data, username, client_ip):
        """Handle text message from authenticated client."""
        message = command_data.get('message', '')
        self.logger.info(f"Message from user '{username}': {message}")
        print(f"Message from user '{username}': {message}")
        self.send_response(conn, aes_cipher, {'status': 'success', 'message': 'Message received'})
    
    def send_response(self, conn, aes_cipher, response_data):
        """Send encrypted response to client."""
        response_json = json.dumps(response_data).encode()
        encrypted_response = aes_cipher.encrypt(response_json)
        conn.sendall(encrypted_response)


if __name__ == "__main__":
    import sys
    
    # Check if config validation is requested
    if len(sys.argv) > 1 and sys.argv[1] == '--validate-config':
        config = get_config()
        errors = config.validate_config()
        if errors:
            print("Configuration errors found:")
            for error in errors:
                print(f"  - {error}")
            sys.exit(1)
        else:
            print("Configuration is valid")
            sys.exit(0)
    
    server = SecureFileTransferServer()
    try:
        server.start_server()
    except KeyboardInterrupt:
        print("\nServer shutdown")
        server.logger.info("Server shutdown by user")
    except Exception as e:
        print(f"Server error: {e}")
        server.logger.critical(f"Server error: {e}")