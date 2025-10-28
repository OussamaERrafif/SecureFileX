import socket
import json
import os
import getpass
from AESCipher import AESCipher  
from KeyManager import KeyManager
from FileHandler import FileHandler
from Logger import get_logger
from Config import get_config


class SecureFileTransferClient:
    """
    Secure file transfer client with encryption, authentication, and integrity verification.
    """
    
    def __init__(self, host=None, port=None):
        self.config = get_config()
        self.host = host or self.config.client_config.default_host
        self.port = port or self.config.client_config.default_port
        self.key_manager = KeyManager()
        self.aes_cipher = None
        self.session_token = None
        self.username = None
        self.logger = get_logger('Client')
    
    def connect(self):
        """Connect to the file transfer server."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.config.client_config.connection_timeout)
        
        try:
            self.socket.connect((self.host, self.port))
            self.logger.info(f"Connected to server at {self.host}:{self.port}")
            print(f"Connected to server at {self.host}:{self.port}")
        except Exception as e:
            self.logger.error(f"Failed to connect to {self.host}:{self.port}: {e}")
            raise Exception(f"Connection failed: {e}")
        
        # Receive RSA public key from server
        rsa_public_key_data = self.socket.recv(4096)
        with open('received_public_key.pem', 'wb') as f:
            f.write(rsa_public_key_data)
        
        # Import server's public key and generate symmetric key
        self.key_manager.import_rsa_public_key('received_public_key.pem')
        self.key_manager.generate_symmetric_key()
        
        # Send encrypted symmetric key to server
        encrypted_symmetric_key = self.key_manager.encrypt_symmetric_key(
            self.key_manager.get_symmetric_key()
        )
        self.socket.sendall(encrypted_symmetric_key)
        
        # Initialize AES cipher
        self.aes_cipher = AESCipher(self.key_manager.get_symmetric_key())
        
        # Perform authentication
        if not self.authenticate():
            raise Exception("Authentication failed")
        
        self.logger.info(f"Authenticated as user: {self.username}")
        print(f"Authenticated as user: {self.username}")
    
    def authenticate(self):
        """Authenticate with the server."""
        # Wait for authentication request
        response = self.receive_response()
        if response.get('status') != 'auth_required':
            print(f"Unexpected server response: {response}")
            return False
        
        print(response.get('message', 'Authentication required'))
        
        # Get credentials from user
        username = input("Username: ")
        password = getpass.getpass("Password: ")
        
        # Send credentials
        auth_data = {
            'username': username,
            'password': password
        }
        auth_json = json.dumps(auth_data).encode()
        encrypted_auth = self.aes_cipher.encrypt(auth_json)
        self.socket.sendall(encrypted_auth)
        
        # Receive authentication response
        response = self.receive_response()
        if response.get('status') == 'auth_success':
            self.session_token = response.get('token')
            self.username = username
            print(f"✓ {response.get('message', 'Authentication successful')}")
            return True
        else:
            print(f"✗ {response.get('message', 'Authentication failed')}")
            return False
    
    def disconnect(self):
        """Disconnect from the server."""
        if hasattr(self, 'socket'):
            try:
                self.send_command({'command': 'QUIT'})
                response = self.receive_response()
                print(f"Server: {response.get('status', 'disconnected')}")
            except:
                pass
            finally:
                self.socket.close()
        
        # Clean up temporary files
        if os.path.exists('received_public_key.pem'):
            os.remove('received_public_key.pem')
    
    def send_command(self, command_data):
        """Send encrypted command to server with authentication token."""
        # Add session token to all commands
        if self.session_token:
            command_data['token'] = self.session_token
            
        command_json = json.dumps(command_data).encode()
        encrypted_command = self.aes_cipher.encrypt(command_json)
        self.socket.sendall(encrypted_command)
    
    def receive_response(self):
        """Receive encrypted response from server."""
        encrypted_response = self.socket.recv(4096)
        if not encrypted_response:
            return {'status': 'error', 'message': 'No response from server'}
        
        decrypted_response = self.aes_cipher.decrypt(encrypted_response)
        return json.loads(decrypted_response.decode())
    
    def upload_file(self, file_path):
        """Upload a file to the server with integrity verification."""
        if not os.path.exists(file_path):
            self.logger.error(f"File not found: {file_path}")
            print(f"Error: File {file_path} not found")
            return False
        
        try:
            # Calculate file metadata
            filename = os.path.basename(file_path)
            file_size = FileHandler.get_file_size(file_path)
            
            # Check file size limit
            if file_size > self.config.server_config.max_file_size:
                self.logger.error(f"File too large: {file_size} bytes")
                print(f"Error: File too large ({file_size} bytes). Max size: {self.config.server_config.max_file_size} bytes")
                return False
            
            file_hash = FileHandler.calculate_file_hash(file_path)
            
            self.logger.info(f"Uploading {filename} ({file_size} bytes)")
            print(f"Uploading {filename} ({file_size} bytes)")
            print(f"File hash: {file_hash}")
            
            # Send upload command with metadata
            upload_command = {
                'command': 'UPLOAD',
                'filename': filename,
                'file_size': file_size,
                'file_hash': file_hash
            }
            self.send_command(upload_command)
            
            # Wait for server ready response
            response = self.receive_response()
            if response.get('status') != 'ready':
                self.logger.error(f"Server not ready: {response.get('message')}")
                print(f"Server not ready: {response.get('message', 'Unknown error')}")
                return False
            
            # Send file chunks
            total_sent = 0
            chunk_size = self.config.client_config.chunk_size
            
            for chunk in FileHandler.read_file_chunks(file_path, chunk_size=chunk_size):
                encrypted_chunk = self.aes_cipher.encrypt(chunk)
                self.socket.sendall(encrypted_chunk)
                total_sent += len(chunk)
                
                progress = (total_sent / file_size) * 100
                print(f"Upload progress: {progress:.1f}%", end='\r')
            
            print()  # New line after progress
            
            # Wait for upload completion response
            response = self.receive_response()
            if response.get('status') == 'success':
                self.logger.info(f"Upload successful: {filename}")
                print(f"✓ {response.get('message', 'File uploaded successfully')}")
                return True
            else:
                self.logger.error(f"Upload failed: {response.get('message')}")
                print(f"✗ Upload failed: {response.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error uploading file {file_path}: {e}")
            print(f"Error uploading file: {e}")
            return False
    
    def send_message(self, message):
        """Send a text message to the server."""
        message_command = {
            'command': 'MESSAGE',
            'message': message
        }
        self.send_command(message_command)
        
        response = self.receive_response()
        if response.get('status') == 'success':
            print(f"✓ {response.get('message', 'Message sent')}")
        else:
            print(f"✗ Error: {response.get('message', 'Unknown error')}")
    
    def list_files(self):
        """List available files on the server."""
        list_command = {'command': 'LIST'}
        self.send_command(list_command)
        
        response = self.receive_response()
        if response.get('status') == 'success':
            files = response.get('files', [])
            if files:
                print(f"\nAvailable files ({response.get('count', 0)}):")
                print(f"{'Filename':<40} {'Size':<15}")
                print("-" * 55)
                for file_info in files:
                    filename = file_info['filename']
                    size = file_info['size']
                    size_str = self._format_size(size)
                    print(f"{filename:<40} {size_str:<15}")
            else:
                print("No files available on server")
        else:
            print(f"✗ Error: {response.get('message', 'Unknown error')}")
    
    def download_file(self, filename, save_path=None):
        """Download a file from the server with integrity verification."""
        try:
            # Use filename as save path if not specified
            if save_path is None:
                save_path = filename
            
            self.logger.info(f"Requesting download: {filename}")
            print(f"Downloading {filename}...")
            
            # Send download command
            download_command = {
                'command': 'DOWNLOAD',
                'filename': filename
            }
            self.send_command(download_command)
            
            # Wait for server response with file metadata
            response = self.receive_response()
            if response.get('status') != 'ready':
                self.logger.error(f"Download failed: {response.get('message')}")
                print(f"✗ Download failed: {response.get('message', 'Unknown error')}")
                return False
            
            file_size = response.get('file_size')
            expected_hash = response.get('file_hash')
            
            print(f"File size: {self._format_size(file_size)}")
            print(f"File hash: {expected_hash}")
            
            # Receive file chunks
            received_chunks = []
            total_received = 0
            
            while total_received < file_size:
                encrypted_chunk = self.socket.recv(8192)
                if not encrypted_chunk:
                    break
                
                decrypted_chunk = self.aes_cipher.decrypt(encrypted_chunk)
                received_chunks.append(decrypted_chunk)
                total_received += len(decrypted_chunk)
                
                progress = (total_received / file_size) * 100
                print(f"Download progress: {progress:.1f}%", end='\r')
            
            print()  # New line after progress
            
            # Write file
            try:
                FileHandler.write_file_chunks(save_path, received_chunks)
                
                # Verify file integrity
                if FileHandler.verify_file_integrity(save_path, expected_hash):
                    self.logger.info(f"Download successful: {filename}")
                    print(f"✓ File {filename} downloaded and verified successfully")
                    return True
                else:
                    os.remove(save_path)  # Remove corrupted file
                    self.logger.error(f"Download failed: integrity verification failed for {filename}")
                    print(f"✗ Download failed: File integrity verification failed")
                    return False
                    
            except Exception as e:
                self.logger.error(f"Error writing downloaded file {filename}: {e}")
                print(f"✗ Error writing file: {e}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error downloading file {filename}: {e}")
            print(f"✗ Error downloading file: {e}")
            return False
    
    def _format_size(self, size_bytes):
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
    
    def send_message(self, message):
        """Send a text message to the server."""
        message_command = {
            'command': 'MESSAGE',
            'message': message
        }
        self.send_command(message_command)
        
        response = self.receive_response()
        if response.get('status') == 'success':
            print(f"✓ {response.get('message', 'Message sent')}")
        else:
            print(f"✗ Error: {response.get('message', 'Unknown error')}")
    
    def interactive_mode(self):
        """Run client in interactive mode."""
        print(f"\nSecureFileX Client - Welcome {self.username}")
        print("Commands:")
        print("  upload <file_path>     - Upload a file")
        print("  download <filename>    - Download a file")
        print("  list                   - List available files")
        print("  message <text>         - Send a text message")
        print("  quit                   - Exit client")
        print()
        
        while True:
            try:
                user_input = input("SecureFileX> ").strip()
                if not user_input:
                    continue
                
                parts = user_input.split(' ', 1)
                command = parts[0].lower()
                
                if command == 'quit' or command == 'exit':
                    break
                elif command == 'upload':
                    if len(parts) > 1:
                        file_path = parts[1].strip()
                        self.upload_file(file_path)
                    else:
                        print("Usage: upload <file_path>")
                elif command == 'download':
                    if len(parts) > 1:
                        filename = parts[1].strip()
                        self.download_file(filename)
                    else:
                        print("Usage: download <filename>")
                elif command == 'list':
                    self.list_files()
                elif command == 'message':
                    if len(parts) > 1:
                        message = parts[1]
                        self.send_message(message)
                    else:
                        print("Usage: message <text>")
                else:
                    print(f"Unknown command: {command}")
                    
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"Error: {e}")


def main():
    """Main function to run the secure file transfer client."""
    client = SecureFileTransferClient()
    
    try:
        client.connect()
        client.interactive_mode()
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()