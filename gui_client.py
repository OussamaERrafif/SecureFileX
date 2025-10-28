#!/usr/bin/env python3
"""
SecureFileX GUI Client
A comprehensive Tkinter-based graphical user interface for SecureFileX
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import queue
import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from Config import get_config
from Logger import get_logger
from KeyManager import KeyManager
from AESCipher import AESCipher
from FileHandler import FileHandler
import socket


import socket


class GUISecureFileTransferClient:
    """
    GUI-compatible secure file transfer client with custom authentication.
    Modified version of SecureFileTransferClient that accepts username/password parameters.
    """
    
    def __init__(self, host=None, port=None):
        self.config = get_config()
        self.host = host or self.config.client_config.default_host
        self.port = port or self.config.client_config.default_port
        self.key_manager = KeyManager()
        self.aes_cipher = None
        self.session_token = None
        self.username = None
        self.logger = get_logger('GUIClient')
    
    def connect(self):
        """Connect to the file transfer server."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.config.client_config.connection_timeout)
        
        try:
            self.socket.connect((self.host, self.port))
            self.logger.info(f"Connected to server at {self.host}:{self.port}")
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
    
    def authenticate(self, username, password):
        """Authenticate with the server using provided credentials."""
        # Wait for authentication request
        response = self.receive_response()
        if response.get('status') != 'auth_required':
            self.logger.error(f"Unexpected server response: {response}")
            return False
        
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
            self.logger.info(f"Authenticated as user: {username}")
            return True
        else:
            self.logger.error(f"Authentication failed: {response.get('message')}")
            return False
    
    def disconnect(self):
        """Disconnect from the server."""
        if hasattr(self, 'socket'):
            try:
                self.send_command({'command': 'QUIT'})
                response = self.receive_response()
            except:
                pass
            finally:
                self.socket.close()
        
        # Clean up temporary files
        if os.path.exists('received_public_key.pem'):
            os.remove('received_public_key.pem')
    
    def send_command(self, command_data):
        """Send encrypted command to server with authentication token."""
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
            return False
        
        try:
            # Calculate file metadata
            filename = os.path.basename(file_path)
            file_size = FileHandler.get_file_size(file_path)
            
            # Check file size limit
            if file_size > self.config.server_config.max_file_size:
                self.logger.error(f"File too large: {file_size} bytes")
                return False
            
            file_hash = FileHandler.calculate_file_hash(file_path)
            
            self.logger.info(f"Uploading {filename} ({file_size} bytes)")
            
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
                return False
            
            # Send file chunks
            chunk_size = self.config.client_config.chunk_size
            
            for chunk in FileHandler.read_file_chunks(file_path, chunk_size=chunk_size):
                encrypted_chunk = self.aes_cipher.encrypt(chunk)
                self.socket.sendall(encrypted_chunk)
            
            # Wait for upload completion response
            response = self.receive_response()
            if response.get('status') == 'success':
                self.logger.info(f"Upload successful: {filename}")
                return True
            else:
                self.logger.error(f"Upload failed: {response.get('message')}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error uploading file {file_path}: {e}")
            return False
    
    def list_files(self):
        """List available files on the server."""
        list_command = {'command': 'LIST'}
        self.send_command(list_command)
        
        response = self.receive_response()
        if response.get('status') == 'success':
            files = response.get('files', [])
            return [file_info['filename'] for file_info in files]
        else:
            self.logger.error(f"Failed to list files: {response.get('message')}")
            return []
    
    def download_file(self, filename, save_path=None):
        """Download a file from the server with integrity verification."""
        try:
            if save_path is None:
                save_path = filename
            
            self.logger.info(f"Requesting download: {filename}")
            
            # Send download command
            download_command = {
                'command': 'DOWNLOAD',
                'filename': filename
            }
            self.send_command(download_command)
            
            # Receive file metadata
            response = self.receive_response()
            if response.get('status') != 'ready':
                self.logger.error(f"Download failed: {response.get('message')}")
                return False
            
            file_size = response.get('file_size')
            expected_hash = response.get('file_hash')
            
            # Receive file chunks
            received_data = b''
            chunk_size = self.config.client_config.chunk_size
            
            while len(received_data) < file_size:
                encrypted_chunk = self.socket.recv(chunk_size)
                if not encrypted_chunk:
                    break
                chunk = self.aes_cipher.decrypt(encrypted_chunk)
                received_data += chunk
            
            # Write to file
            with open(save_path, 'wb') as f:
                f.write(received_data)
            
            # Verify integrity
            actual_hash = FileHandler.calculate_file_hash(save_path)
            if actual_hash == expected_hash:
                self.logger.info(f"Download successful: {filename}")
                return True
            else:
                self.logger.error(f"Integrity check failed for {filename}")
                os.remove(save_path)
                return False
                
        except Exception as e:
            self.logger.error(f"Error downloading file {filename}: {e}")
            return False


class SecureFileXGUI:
    """Main GUI application for SecureFileX"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SecureFileX - Secure File Transfer")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Initialize variables
        self.client = None
        self.connected = False
        self.authenticated = False
        self.config = get_config()
        self.logger = get_logger('GUI')
        self.message_queue = queue.Queue()
        
        # Configure style
        self.setup_styles()
        
        # Create GUI components
        self.create_menu()
        self.create_connection_frame()
        self.create_auth_frame()
        self.create_file_operations_frame()
        self.create_console_frame()
        self.create_status_bar()
        
        # Start message queue processor
        self.process_messages()
        
        # Log startup
        self.log_message("SecureFileX GUI started")
    
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Connected.TLabel', foreground='green', font=('Arial', 10, 'bold'))
        style.configure('Disconnected.TLabel', foreground='red', font=('Arial', 10, 'bold'))
        style.configure('Title.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Action.TButton', padding=5)
    
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Upload File", command=self.upload_file)
        file_menu.add_command(label="Download File", command=self.download_file_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Connection menu
        conn_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Connection", menu=conn_menu)
        conn_menu.add_command(label="Connect", command=self.connect_to_server)
        conn_menu.add_command(label="Disconnect", command=self.disconnect_from_server)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Refresh File List", command=self.refresh_file_list)
        tools_menu.add_command(label="Clear Console", command=self.clear_console)
        tools_menu.add_command(label="Settings", command=self.show_settings)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_connection_frame(self):
        """Create connection settings frame"""
        frame = ttk.LabelFrame(self.root, text="Server Connection", padding=10)
        frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Host
        ttk.Label(frame, text="Host:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.host_entry = ttk.Entry(frame, width=30)
        self.host_entry.insert(0, self.config.client_config.default_host)
        self.host_entry.grid(row=0, column=1, padx=5, pady=2)
        
        # Port
        ttk.Label(frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.port_entry = ttk.Entry(frame, width=10)
        self.port_entry.insert(0, str(self.config.client_config.default_port))
        self.port_entry.grid(row=0, column=3, padx=5, pady=2)
        
        # Connect button
        self.connect_btn = ttk.Button(frame, text="Connect", command=self.connect_to_server, 
                                     style='Action.TButton')
        self.connect_btn.grid(row=0, column=4, padx=5, pady=2)
        
        # Disconnect button
        self.disconnect_btn = ttk.Button(frame, text="Disconnect", command=self.disconnect_from_server,
                                        style='Action.TButton', state=tk.DISABLED)
        self.disconnect_btn.grid(row=0, column=5, padx=5, pady=2)
        
        # Status label
        self.status_label = ttk.Label(frame, text="● Disconnected", style='Disconnected.TLabel')
        self.status_label.grid(row=0, column=6, padx=10, pady=2)
    
    def create_auth_frame(self):
        """Create authentication frame"""
        frame = ttk.LabelFrame(self.root, text="Authentication", padding=10)
        frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Username
        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.username_entry = ttk.Entry(frame, width=20)
        self.username_entry.insert(0, "admin")
        self.username_entry.grid(row=0, column=1, padx=5, pady=2)
        
        # Password
        ttk.Label(frame, text="Password:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.password_entry = ttk.Entry(frame, width=20, show="*")
        self.password_entry.insert(0, "admin123")
        self.password_entry.grid(row=0, column=3, padx=5, pady=2)
        
        # Login button
        self.login_btn = ttk.Button(frame, text="Login", command=self.authenticate,
                                   style='Action.TButton', state=tk.DISABLED)
        self.login_btn.grid(row=0, column=4, padx=5, pady=2)
        
        # Auth status
        self.auth_label = ttk.Label(frame, text="Not Authenticated")
        self.auth_label.grid(row=0, column=5, padx=10, pady=2)
    
    def create_file_operations_frame(self):
        """Create file operations frame"""
        frame = ttk.LabelFrame(self.root, text="File Operations", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left panel - Actions
        left_panel = ttk.Frame(frame)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5)
        
        ttk.Label(left_panel, text="Actions", style='Title.TLabel').pack(pady=5)
        
        self.upload_btn = ttk.Button(left_panel, text="📤 Upload File", 
                                     command=self.upload_file, width=20, state=tk.DISABLED)
        self.upload_btn.pack(pady=5)
        
        self.download_btn = ttk.Button(left_panel, text="📥 Download File",
                                      command=self.download_file_dialog, width=20, state=tk.DISABLED)
        self.download_btn.pack(pady=5)
        
        self.refresh_btn = ttk.Button(left_panel, text="🔄 Refresh List",
                                     command=self.refresh_file_list, width=20, state=tk.DISABLED)
        self.refresh_btn.pack(pady=5)
        
        self.delete_btn = ttk.Button(left_panel, text="🗑️ Delete File",
                                    command=self.delete_file, width=20, state=tk.DISABLED)
        self.delete_btn.pack(pady=5)
        
        # Progress bar
        ttk.Label(left_panel, text="Transfer Progress:").pack(pady=(20, 5))
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(left_panel, mode='determinate',
                                           variable=self.progress_var, length=200)
        self.progress_bar.pack(pady=5)
        self.progress_label = ttk.Label(left_panel, text="0%")
        self.progress_label.pack()
        
        # Right panel - File list
        right_panel = ttk.Frame(frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        ttk.Label(right_panel, text="Server Files", style='Title.TLabel').pack(pady=5)
        
        # File listbox with scrollbar
        list_frame = ttk.Frame(right_panel)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.file_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set,
                                       font=('Courier', 10))
        self.file_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.file_listbox.yview)
        
        # Bind double-click to download
        self.file_listbox.bind('<Double-Button-1>', lambda e: self.download_file_dialog())
    
    def create_console_frame(self):
        """Create console output frame"""
        frame = ttk.LabelFrame(self.root, text="Console Output", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Console text widget
        self.console = scrolledtext.ScrolledText(frame, height=10, state=tk.DISABLED,
                                                 wrap=tk.WORD, font=('Courier', 9))
        self.console.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for colored output
        self.console.tag_config('error', foreground='red')
        self.console.tag_config('success', foreground='green')
        self.console.tag_config('info', foreground='blue')
        self.console.tag_config('warning', foreground='orange')
    
    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def log_message(self, message, level='info'):
        """Add message to console"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] {message}\n"
        
        self.console.config(state=tk.NORMAL)
        self.console.insert(tk.END, formatted_message, level)
        self.console.see(tk.END)
        self.console.config(state=tk.DISABLED)
        
        # Also log to file
        if level == 'error':
            self.logger.error(message)
        elif level == 'warning':
            self.logger.warning(message)
        elif level == 'success':
            self.logger.info(message)
        else:
            self.logger.info(message)
    
    def update_status(self, message):
        """Update status bar"""
        self.status_bar.config(text=message)
    
    def clear_console(self):
        """Clear console output"""
        self.console.config(state=tk.NORMAL)
        self.console.delete(1.0, tk.END)
        self.console.config(state=tk.DISABLED)
        self.log_message("Console cleared")
    
    def connect_to_server(self):
        """Connect to the server"""
        host = self.host_entry.get()
        port = self.port_entry.get()
        
        if not host or not port:
            messagebox.showerror("Error", "Please enter host and port")
            return
        
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Error", "Port must be a number")
            return
        
        def do_connect():
            try:
                self.log_message(f"Connecting to {host}:{port}...", 'info')
                self.client = GUISecureFileTransferClient(host=host, port=port)
                self.client.connect()
                
                self.message_queue.put(('connected', None))
                self.log_message(f"Connected to server at {host}:{port}", 'success')
                
            except Exception as e:
                self.message_queue.put(('error', f"Connection failed: {e}"))
                self.log_message(f"Connection failed: {e}", 'error')
        
        # Run connection in separate thread
        thread = threading.Thread(target=do_connect, daemon=True)
        thread.start()
        
        self.update_status("Connecting...")
    
    def disconnect_from_server(self):
        """Disconnect from the server"""
        if self.client:
            try:
                self.client.disconnect()
                self.log_message("Disconnected from server", 'info')
            except:
                pass
            
            self.client = None
        
        self.connected = False
        self.authenticated = False
        self.update_ui_state()
        self.update_status("Disconnected")
    
    def authenticate(self):
        """Authenticate with the server"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter username and password")
            return
        
        def do_auth():
            try:
                self.log_message(f"Authenticating as {username}...", 'info')
                success = self.client.authenticate(username, password)
                
                if success:
                    self.message_queue.put(('authenticated', username))
                    self.log_message(f"Authentication successful for {username}", 'success')
                else:
                    self.message_queue.put(('error', "Authentication failed"))
                    self.log_message("Authentication failed", 'error')
                    
            except Exception as e:
                self.message_queue.put(('error', f"Authentication error: {e}"))
                self.log_message(f"Authentication error: {e}", 'error')
        
        thread = threading.Thread(target=do_auth, daemon=True)
        thread.start()
    
    def upload_file(self):
        """Upload a file to the server"""
        if not self.authenticated:
            messagebox.showwarning("Warning", "Please authenticate first")
            return
        
        filepath = filedialog.askopenfilename(title="Select file to upload")
        if not filepath:
            return
        
        def do_upload():
            try:
                self.log_message(f"Uploading {os.path.basename(filepath)}...", 'info')
                self.message_queue.put(('uploading', filepath))
                
                success = self.client.upload_file(filepath)
                
                if success:
                    self.message_queue.put(('upload_complete', filepath))
                    self.log_message(f"Upload successful: {os.path.basename(filepath)}", 'success')
                else:
                    self.message_queue.put(('error', f"Upload failed: {filepath}"))
                    self.log_message(f"Upload failed: {os.path.basename(filepath)}", 'error')
                    
            except Exception as e:
                self.message_queue.put(('error', f"Upload error: {e}"))
                self.log_message(f"Upload error: {e}", 'error')
        
        thread = threading.Thread(target=do_upload, daemon=True)
        thread.start()
    
    def download_file_dialog(self):
        """Show download file dialog"""
        if not self.authenticated:
            messagebox.showwarning("Warning", "Please authenticate first")
            return
        
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showinfo("Info", "Please select a file to download")
            return
        
        filename = self.file_listbox.get(selection[0])
        
        save_path = filedialog.asksaveasfilename(
            title="Save file as",
            initialfile=filename,
            defaultextension=Path(filename).suffix
        )
        
        if not save_path:
            return
        
        def do_download():
            try:
                self.log_message(f"Downloading {filename}...", 'info')
                self.message_queue.put(('downloading', filename))
                
                success = self.client.download_file(filename, save_path)
                
                if success:
                    self.message_queue.put(('download_complete', filename))
                    self.log_message(f"Download successful: {filename}", 'success')
                else:
                    self.message_queue.put(('error', f"Download failed: {filename}"))
                    self.log_message(f"Download failed: {filename}", 'error')
                    
            except Exception as e:
                self.message_queue.put(('error', f"Download error: {e}"))
                self.log_message(f"Download error: {e}", 'error')
        
        thread = threading.Thread(target=do_download, daemon=True)
        thread.start()
    
    def refresh_file_list(self):
        """Refresh the list of files from server"""
        if not self.authenticated:
            messagebox.showwarning("Warning", "Please authenticate first")
            return
        
        def do_refresh():
            try:
                self.log_message("Refreshing file list...", 'info')
                files = self.client.list_files()
                
                self.message_queue.put(('file_list', files))
                self.log_message(f"File list refreshed ({len(files)} files)", 'success')
                
            except Exception as e:
                self.message_queue.put(('error', f"Failed to get file list: {e}"))
                self.log_message(f"Failed to get file list: {e}", 'error')
        
        thread = threading.Thread(target=do_refresh, daemon=True)
        thread.start()
    
    def delete_file(self):
        """Delete a file from the server"""
        if not self.authenticated:
            messagebox.showwarning("Warning", "Please authenticate first")
            return
        
        selection = self.file_listbox.curselection()
        if not selection:
            messagebox.showinfo("Info", "Please select a file to delete")
            return
        
        filename = self.file_listbox.get(selection[0])
        
        if not messagebox.askyesno("Confirm Delete", f"Delete {filename}?"):
            return
        
        self.log_message(f"Delete feature not yet implemented for {filename}", 'warning')
        messagebox.showinfo("Info", "Delete feature coming soon")
    
    def update_ui_state(self):
        """Update UI elements based on connection state"""
        if self.connected:
            self.connect_btn.config(state=tk.DISABLED)
            self.disconnect_btn.config(state=tk.NORMAL)
            self.login_btn.config(state=tk.NORMAL)
            self.status_label.config(text="● Connected", style='Connected.TLabel')
            
            if self.authenticated:
                self.upload_btn.config(state=tk.NORMAL)
                self.download_btn.config(state=tk.NORMAL)
                self.refresh_btn.config(state=tk.NORMAL)
                self.delete_btn.config(state=tk.NORMAL)
                self.auth_label.config(text=f"✓ Authenticated as {self.username_entry.get()}",
                                      foreground='green')
            else:
                self.upload_btn.config(state=tk.DISABLED)
                self.download_btn.config(state=tk.DISABLED)
                self.refresh_btn.config(state=tk.DISABLED)
                self.delete_btn.config(state=tk.DISABLED)
                self.auth_label.config(text="Not Authenticated", foreground='black')
        else:
            self.connect_btn.config(state=tk.NORMAL)
            self.disconnect_btn.config(state=tk.DISABLED)
            self.login_btn.config(state=tk.DISABLED)
            self.upload_btn.config(state=tk.DISABLED)
            self.download_btn.config(state=tk.DISABLED)
            self.refresh_btn.config(state=tk.DISABLED)
            self.delete_btn.config(state=tk.DISABLED)
            self.status_label.config(text="● Disconnected", style='Disconnected.TLabel')
            self.auth_label.config(text="Not Authenticated", foreground='black')
    
    def process_messages(self):
        """Process messages from background threads"""
        try:
            while True:
                msg_type, msg_data = self.message_queue.get_nowait()
                
                if msg_type == 'connected':
                    self.connected = True
                    self.update_ui_state()
                    self.update_status("Connected")
                    
                elif msg_type == 'authenticated':
                    self.authenticated = True
                    self.update_ui_state()
                    self.update_status(f"Authenticated as {msg_data}")
                    # Auto-refresh file list after authentication
                    self.refresh_file_list()
                    
                elif msg_type == 'file_list':
                    self.file_listbox.delete(0, tk.END)
                    for filename in msg_data:
                        self.file_listbox.insert(tk.END, filename)
                    self.update_status(f"{len(msg_data)} files available")
                    
                elif msg_type == 'uploading':
                    self.progress_var.set(0)
                    self.update_status(f"Uploading {os.path.basename(msg_data)}...")
                    
                elif msg_type == 'upload_complete':
                    self.progress_var.set(100)
                    self.progress_label.config(text="100%")
                    self.update_status("Upload complete")
                    # Refresh file list
                    self.refresh_file_list()
                    
                elif msg_type == 'downloading':
                    self.progress_var.set(0)
                    self.update_status(f"Downloading {msg_data}...")
                    
                elif msg_type == 'download_complete':
                    self.progress_var.set(100)
                    self.progress_label.config(text="100%")
                    self.update_status("Download complete")
                    
                elif msg_type == 'error':
                    messagebox.showerror("Error", msg_data)
                    self.update_status("Error occurred")
                    
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(100, self.process_messages)
    
    def show_settings(self):
        """Show settings dialog"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("500x400")
        settings_window.transient(self.root)
        
        # Configuration display
        ttk.Label(settings_window, text="Current Configuration", 
                 style='Title.TLabel').pack(pady=10)
        
        config_text = scrolledtext.ScrolledText(settings_window, height=15, width=60)
        config_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Display config
        config_text.insert(tk.END, f"Server Configuration:\n")
        config_text.insert(tk.END, f"  Host: {self.config.server_config.host}\n")
        config_text.insert(tk.END, f"  Port: {self.config.server_config.port}\n")
        config_text.insert(tk.END, f"  Upload Dir: {self.config.server_config.upload_dir}\n")
        config_text.insert(tk.END, f"  Max File Size: {self.config.server_config.max_file_size} bytes\n\n")
        
        config_text.insert(tk.END, f"Client Configuration:\n")
        config_text.insert(tk.END, f"  Default Host: {self.config.client_config.default_host}\n")
        config_text.insert(tk.END, f"  Default Port: {self.config.client_config.default_port}\n")
        config_text.insert(tk.END, f"  Chunk Size: {self.config.client_config.chunk_size}\n")
        config_text.insert(tk.END, f"  Connection Timeout: {self.config.client_config.connection_timeout}s\n\n")
        
        config_text.insert(tk.END, f"Security Configuration:\n")
        config_text.insert(tk.END, f"  RSA Key Size: {self.config.security_config.rsa_key_size}\n")
        config_text.insert(tk.END, f"  AES Key Size: {self.config.security_config.aes_key_size}\n")
        config_text.insert(tk.END, f"  Hash Algorithm: {self.config.security_config.hash_algorithm}\n")
        
        config_text.config(state=tk.DISABLED)
        
        ttk.Button(settings_window, text="Close", 
                  command=settings_window.destroy).pack(pady=10)
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
SecureFileX GUI Client
Version 1.0

A comprehensive secure file transfer system with:
• End-to-End AES-256 encryption
• RSA-2048 key exchange
• SHA-256 file integrity verification
• Session-based authentication

Created for secure file transfers over network.

© 2024 SecureFileX
        """
        messagebox.showinfo("About SecureFileX", about_text)
    
    def on_closing(self):
        """Handle window closing"""
        if self.connected:
            if messagebox.askokcancel("Quit", "Disconnect and quit?"):
                self.disconnect_from_server()
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    """Main entry point"""
    root = tk.Tk()
    app = SecureFileXGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == '__main__':
    main()
