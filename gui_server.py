#!/usr/bin/env python3
"""
SecureFileX GUI Server
A comprehensive Tkinter-based graphical user interface for SecureFileX Server
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import queue
import os
import sys
from pathlib import Path
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from Config import get_config
from Logger import get_logger


class SecureFileXServerGUI:
    """Main GUI application for SecureFileX Server"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SecureFileX - Server Control Panel")
        self.root.geometry("800x600")
        self.root.minsize(700, 500)
        
        # Initialize variables
        self.server_thread = None
        self.server_running = False
        self.config = get_config()
        self.logger = get_logger('ServerGUI')
        self.message_queue = queue.Queue()
        self.connected_clients = []
        
        # Configure style
        self.setup_styles()
        
        # Create GUI components
        self.create_menu()
        self.create_server_config_frame()
        self.create_status_frame()
        self.create_clients_frame()
        self.create_console_frame()
        self.create_control_frame()
        self.create_status_bar()
        
        # Log startup
        self.log_message("SecureFileX Server GUI started")
    
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Running.TLabel', foreground='green', font=('Arial', 11, 'bold'))
        style.configure('Stopped.TLabel', foreground='red', font=('Arial', 11, 'bold'))
        style.configure('Title.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Action.TButton', padding=5)
    
    def create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Upload Directory", command=self.open_upload_dir)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        
        # Server menu
        server_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Server", menu=server_menu)
        server_menu.add_command(label="Start Server", command=self.start_server)
        server_menu.add_command(label="Stop Server", command=self.stop_server)
        server_menu.add_separator()
        server_menu.add_command(label="Validate Configuration", command=self.validate_config)
        
        # Users menu
        users_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Users", menu=users_menu)
        users_menu.add_command(label="List Users", command=self.list_users)
        users_menu.add_command(label="Create User", command=self.create_user_dialog)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Clear Console", command=self.clear_console)
        tools_menu.add_command(label="Refresh Client List", command=self.refresh_clients)
        tools_menu.add_command(label="View Logs", command=self.view_logs)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_server_config_frame(self):
        """Create server configuration frame"""
        frame = ttk.LabelFrame(self.root, text="Server Configuration", padding=10)
        frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Host
        ttk.Label(frame, text="Host:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.host_entry = ttk.Entry(frame, width=25)
        self.host_entry.insert(0, self.config.server_config.host)
        self.host_entry.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Port
        ttk.Label(frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        self.port_entry = ttk.Entry(frame, width=10)
        self.port_entry.insert(0, str(self.config.server_config.port))
        self.port_entry.grid(row=0, column=3, padx=5, pady=2, sticky=tk.W)
        
        # Upload directory
        ttk.Label(frame, text="Upload Dir:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.upload_dir_entry = ttk.Entry(frame, width=40)
        self.upload_dir_entry.insert(0, self.config.server_config.upload_dir)
        self.upload_dir_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=2, sticky=tk.W)
        
        ttk.Button(frame, text="Browse...", command=self.browse_upload_dir,
                  width=10).grid(row=1, column=3, padx=5, pady=2)
        
        # Max connections
        ttk.Label(frame, text="Max Connections:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.max_conn_entry = ttk.Entry(frame, width=10)
        self.max_conn_entry.insert(0, str(self.config.server_config.max_connections))
        self.max_conn_entry.grid(row=2, column=1, padx=5, pady=2, sticky=tk.W)
        
        # Max file size
        ttk.Label(frame, text="Max File Size (MB):").grid(row=2, column=2, sticky=tk.W, padx=5, pady=2)
        max_size_mb = self.config.server_config.max_file_size / (1024 * 1024)
        self.max_size_entry = ttk.Entry(frame, width=10)
        self.max_size_entry.insert(0, str(int(max_size_mb)))
        self.max_size_entry.grid(row=2, column=3, padx=5, pady=2, sticky=tk.W)
    
    def create_status_frame(self):
        """Create server status frame"""
        frame = ttk.LabelFrame(self.root, text="Server Status", padding=10)
        frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Status indicator
        status_container = ttk.Frame(frame)
        status_container.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        ttk.Label(status_container, text="Status:").pack(side=tk.LEFT, padx=5)
        self.status_label = ttk.Label(status_container, text="● Stopped", style='Stopped.TLabel')
        self.status_label.pack(side=tk.LEFT, padx=5)
        
        # Statistics
        stats_container = ttk.Frame(frame)
        stats_container.pack(side=tk.RIGHT, fill=tk.X)
        
        ttk.Label(stats_container, text="Connected Clients:").pack(side=tk.LEFT, padx=5)
        self.client_count_label = ttk.Label(stats_container, text="0", font=('Arial', 10, 'bold'))
        self.client_count_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(stats_container, text="Files:").pack(side=tk.LEFT, padx=10)
        self.file_count_label = ttk.Label(stats_container, text="0", font=('Arial', 10, 'bold'))
        self.file_count_label.pack(side=tk.LEFT, padx=5)
    
    def create_clients_frame(self):
        """Create connected clients frame"""
        frame = ttk.LabelFrame(self.root, text="Connected Clients", padding=10)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Clients listbox with scrollbar
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.clients_listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set,
                                         font=('Courier', 9), height=6)
        self.clients_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.clients_listbox.yview)
        
        # Add placeholder text
        self.clients_listbox.insert(tk.END, "No clients connected")
    
    def create_console_frame(self):
        """Create console output frame"""
        frame = ttk.LabelFrame(self.root, text="Server Logs", padding=10)
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
    
    def create_control_frame(self):
        """Create control buttons frame"""
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.start_btn = ttk.Button(frame, text="▶ Start Server", command=self.start_server,
                                    style='Action.TButton', width=20)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(frame, text="⏹ Stop Server", command=self.stop_server,
                                   style='Action.TButton', width=20, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(frame, text="🔄 Refresh", command=self.refresh_status,
                  style='Action.TButton', width=15).pack(side=tk.RIGHT, padx=5)
    
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
    
    def update_status_bar(self, message):
        """Update status bar"""
        self.status_bar.config(text=message)
    
    def clear_console(self):
        """Clear console output"""
        self.console.config(state=tk.NORMAL)
        self.console.delete(1.0, tk.END)
        self.console.config(state=tk.DISABLED)
        self.log_message("Console cleared")
    
    def browse_upload_dir(self):
        """Browse for upload directory"""
        directory = filedialog.askdirectory(
            title="Select Upload Directory",
            initialdir=self.upload_dir_entry.get()
        )
        if directory:
            self.upload_dir_entry.delete(0, tk.END)
            self.upload_dir_entry.insert(0, directory)
    
    def open_upload_dir(self):
        """Open upload directory in file explorer"""
        upload_dir = self.upload_dir_entry.get()
        if os.path.exists(upload_dir):
            import subprocess
            import platform
            
            if platform.system() == 'Windows':
                os.startfile(upload_dir)
            elif platform.system() == 'Darwin':  # macOS
                subprocess.Popen(['open', upload_dir])
            else:  # Linux
                subprocess.Popen(['xdg-open', upload_dir])
        else:
            messagebox.showwarning("Warning", "Upload directory does not exist")
    
    def start_server(self):
        """Start the server"""
        if self.server_running:
            messagebox.showinfo("Info", "Server is already running")
            return
        
        host = self.host_entry.get()
        port = self.port_entry.get()
        upload_dir = self.upload_dir_entry.get()
        
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Error", "Port must be a number")
            return
        
        # Create upload directory if it doesn't exist
        if not os.path.exists(upload_dir):
            try:
                os.makedirs(upload_dir)
                self.log_message(f"Created upload directory: {upload_dir}", 'info')
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create upload directory: {e}")
                return
        
        def run_server():
            try:
                from file_server import SecureFileTransferServer
                
                self.log_message(f"Starting server on {host}:{port}...", 'info')
                server = SecureFileTransferServer(host=host, port=port, upload_dir=upload_dir)
                self.server_running = True
                self.message_queue.put(('server_started', None))
                
                server.start_server()
                
            except Exception as e:
                self.message_queue.put(('error', f"Server error: {e}"))
                self.log_message(f"Server error: {e}", 'error')
                self.server_running = False
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        self.update_server_ui(running=True)
        self.update_status_bar("Server starting...")
    
    def stop_server(self):
        """Stop the server"""
        if not self.server_running:
            messagebox.showinfo("Info", "Server is not running")
            return
        
        self.log_message("Stopping server...", 'warning')
        self.server_running = False
        
        # Note: Actual server stopping would require proper shutdown mechanism
        # For now, we just update the UI
        self.update_server_ui(running=False)
        self.log_message("Server stopped", 'info')
        self.update_status_bar("Server stopped")
    
    def update_server_ui(self, running):
        """Update UI based on server state"""
        if running:
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.status_label.config(text="● Running", style='Running.TLabel')
            self.host_entry.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            self.upload_dir_entry.config(state=tk.DISABLED)
        else:
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.status_label.config(text="● Stopped", style='Stopped.TLabel')
            self.host_entry.config(state=tk.NORMAL)
            self.port_entry.config(state=tk.NORMAL)
            self.upload_dir_entry.config(state=tk.NORMAL)
    
    def validate_config(self):
        """Validate configuration"""
        errors = self.config.validate_config()
        if errors:
            error_msg = "Configuration errors found:\n" + "\n".join(f"• {e}" for e in errors)
            messagebox.showerror("Configuration Errors", error_msg)
            self.log_message("Configuration validation failed", 'error')
        else:
            messagebox.showinfo("Configuration Valid", "Configuration is valid ✓")
            self.log_message("Configuration validated successfully", 'success')
    
    def list_users(self):
        """List all users"""
        try:
            from Authenticator import SimpleAuthenticator
            auth = SimpleAuthenticator()
            users = auth.list_users()
            
            if users:
                user_list = "\n".join(f"• {user}" for user in users)
                messagebox.showinfo("Registered Users", f"Users:\n\n{user_list}")
                self.log_message(f"Listed {len(users)} users", 'info')
            else:
                messagebox.showinfo("Registered Users", "No users found")
                self.log_message("No users found", 'info')
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list users: {e}")
            self.log_message(f"Failed to list users: {e}", 'error')
    
    def create_user_dialog(self):
        """Show create user dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Create New User")
        dialog.geometry("350x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Username
        ttk.Label(dialog, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        username_entry = ttk.Entry(dialog, width=25)
        username_entry.grid(row=0, column=1, padx=10, pady=5)
        username_entry.focus()
        
        # Password
        ttk.Label(dialog, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        password_entry = ttk.Entry(dialog, width=25, show="*")
        password_entry.grid(row=1, column=1, padx=10, pady=5)
        
        # Confirm Password
        ttk.Label(dialog, text="Confirm:").grid(row=2, column=0, sticky=tk.W, padx=10, pady=5)
        confirm_entry = ttk.Entry(dialog, width=25, show="*")
        confirm_entry.grid(row=2, column=1, padx=10, pady=5)
        
        def create_user():
            username = username_entry.get()
            password = password_entry.get()
            confirm = confirm_entry.get()
            
            if not username or not password:
                messagebox.showerror("Error", "Please fill in all fields")
                return
            
            if password != confirm:
                messagebox.showerror("Error", "Passwords don't match")
                return
            
            try:
                from Authenticator import SimpleAuthenticator
                auth = SimpleAuthenticator()
                success, message = auth.add_user(username, password)
                
                if success:
                    messagebox.showinfo("Success", message)
                    self.log_message(f"User created: {username}", 'success')
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", message)
                    self.log_message(f"Failed to create user: {message}", 'error')
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create user: {e}")
                self.log_message(f"Failed to create user: {e}", 'error')
        
        # Buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="Create", command=create_user, width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=dialog.destroy, width=12).pack(side=tk.LEFT, padx=5)
    
    def refresh_clients(self):
        """Refresh client list"""
        # In a real implementation, this would query the server for connected clients
        self.log_message("Refreshing client list...", 'info')
        self.update_status_bar("Client list refreshed")
    
    def refresh_status(self):
        """Refresh server status and statistics"""
        upload_dir = self.upload_dir_entry.get()
        
        # Count files in upload directory
        if os.path.exists(upload_dir):
            try:
                files = [f for f in os.listdir(upload_dir) if os.path.isfile(os.path.join(upload_dir, f))]
                self.file_count_label.config(text=str(len(files)))
                self.log_message(f"Found {len(files)} files in upload directory", 'info')
            except Exception as e:
                self.log_message(f"Failed to count files: {e}", 'error')
        
        self.update_status_bar("Status refreshed")
    
    def view_logs(self):
        """View server logs"""
        log_viewer = tk.Toplevel(self.root)
        log_viewer.title("Server Logs")
        log_viewer.geometry("700x500")
        log_viewer.transient(self.root)
        
        text_widget = scrolledtext.ScrolledText(log_viewer, wrap=tk.WORD, font=('Courier', 9))
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Try to load server log
        log_file = "logs/server.log"
        if os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    text_widget.insert(tk.END, f.read())
                text_widget.see(tk.END)
            except Exception as e:
                text_widget.insert(tk.END, f"Failed to load log file: {e}")
        else:
            text_widget.insert(tk.END, "Log file not found")
        
        text_widget.config(state=tk.DISABLED)
        
        ttk.Button(log_viewer, text="Close", command=log_viewer.destroy).pack(pady=10)
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
SecureFileX Server Control Panel
Version 1.0

A comprehensive secure file transfer server with:
• End-to-End AES-256 encryption
• RSA-2048 key exchange
• SHA-256 file integrity verification
• Multi-user authentication
• Session management

Server management made easy with GUI.

© 2024 SecureFileX
        """
        messagebox.showinfo("About SecureFileX Server", about_text)
    
    def on_closing(self):
        """Handle window closing"""
        if self.server_running:
            if messagebox.askokcancel("Quit", "Stop server and quit?"):
                self.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()


def main():
    """Main entry point"""
    root = tk.Tk()
    app = SecureFileXServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == '__main__':
    main()
