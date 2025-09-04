import socket
import json
import os
import getpass
from AESCipher import AESCipher  
from KeyManager import KeyManager
from FileHandler import FileHandler


class SecureFileTransferClient:
    """
    Secure file transfer client with encryption, authentication, and integrity verification.
    """
    
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.key_manager = KeyManager()
        self.aes_cipher = None
        self.session_token = None
        self.username = None
    
    def connect(self):
        """Connect to the file transfer server."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        print(f"Connected to server at {self.host}:{self.port}")
        
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
            print(f"Error: File {file_path} not found")
            return False
        
        try:
            # Calculate file metadata
            filename = os.path.basename(file_path)
            file_size = FileHandler.get_file_size(file_path)
            file_hash = FileHandler.calculate_file_hash(file_path)
            
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
                print(f"Server not ready: {response.get('message', 'Unknown error')}")
                return False
            
            # Send file chunks
            total_sent = 0
            for chunk in FileHandler.read_file_chunks(file_path, chunk_size=4096):
                encrypted_chunk = self.aes_cipher.encrypt(chunk)
                self.socket.sendall(encrypted_chunk)
                total_sent += len(chunk)
                
                progress = (total_sent / file_size) * 100
                print(f"Upload progress: {progress:.1f}%", end='\r')
            
            print()  # New line after progress
            
            # Wait for upload completion response
            response = self.receive_response()
            if response.get('status') == 'success':
                print(f"✓ {response.get('message', 'File uploaded successfully')}")
                return True
            else:
                print(f"✗ Upload failed: {response.get('message', 'Unknown error')}")
                return False
                
        except Exception as e:
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
    
    def interactive_mode(self):
        """Run client in interactive mode."""
        print(f"\nSecureFileX Client - Welcome {self.username}")
        print("Commands:")
        print("  upload <file_path> - Upload a file")
        print("  message <text>     - Send a text message")
        print("  quit               - Exit client")
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