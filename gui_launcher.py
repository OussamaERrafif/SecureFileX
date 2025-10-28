#!/usr/bin/env python3
"""
SecureFileX GUI Launcher
Unified launcher for SecureFileX GUI Client and Server
"""

import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))


class SecureFileXLauncher:
    """Main launcher for SecureFileX GUI applications"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("SecureFileX - Launcher")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        
        # Configure style
        self.setup_styles()
        
        # Create GUI
        self.create_header()
        self.create_options()
        self.create_footer()
    
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Title.TLabel', font=('Arial', 20, 'bold'))
        style.configure('Subtitle.TLabel', font=('Arial', 11))
        style.configure('Launch.TButton', font=('Arial', 12), padding=10)
    
    def create_header(self):
        """Create header section"""
        header_frame = ttk.Frame(self.root, padding=20)
        header_frame.pack(fill=tk.X)
        
        # Logo/Title
        title_label = ttk.Label(header_frame, text="🔐 SecureFileX", style='Title.TLabel')
        title_label.pack()
        
        subtitle_label = ttk.Label(header_frame, 
                                   text="Secure File Transfer System",
                                   style='Subtitle.TLabel')
        subtitle_label.pack(pady=5)
        
        # Description
        desc_text = """
End-to-End Encrypted File Transfer
AES-256 | RSA-2048 | SHA-256 Integrity
        """
        desc_label = ttk.Label(header_frame, text=desc_text, justify=tk.CENTER)
        desc_label.pack(pady=10)
        
        # Separator
        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=20)
    
    def create_options(self):
        """Create launch options"""
        options_frame = ttk.Frame(self.root, padding=30)
        options_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(options_frame, text="Select Application to Launch:", 
                 font=('Arial', 12, 'bold')).pack(pady=10)
        
        # Client button
        client_frame = ttk.LabelFrame(options_frame, text="Client Application", padding=15)
        client_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(client_frame, text="Connect to a SecureFileX server\nUpload and download files securely",
                 justify=tk.LEFT).pack(anchor=tk.W)
        
        ttk.Button(client_frame, text="🖥️  Launch Client", 
                  command=self.launch_client, style='Launch.TButton').pack(pady=10)
        
        # Server button
        server_frame = ttk.LabelFrame(options_frame, text="Server Application", padding=15)
        server_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(server_frame, text="Run a SecureFileX server\nManage users and file transfers",
                 justify=tk.LEFT).pack(anchor=tk.W)
        
        ttk.Button(server_frame, text="⚙️  Launch Server", 
                  command=self.launch_server, style='Launch.TButton').pack(pady=10)
    
    def create_footer(self):
        """Create footer section"""
        # Separator
        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=20)
        
        footer_frame = ttk.Frame(self.root, padding=10)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        # CLI option
        ttk.Label(footer_frame, text="Prefer command line?", 
                 font=('Arial', 9)).pack(side=tk.LEFT, padx=10)
        
        ttk.Button(footer_frame, text="View CLI Help", 
                  command=self.show_cli_help).pack(side=tk.LEFT, padx=5)
        
        # Exit button
        ttk.Button(footer_frame, text="Exit", 
                  command=self.root.quit).pack(side=tk.RIGHT, padx=10)
    
    def launch_client(self):
        """Launch the GUI client"""
        try:
            subprocess.Popen([sys.executable, 'gui_client.py'])
            messagebox.showinfo("Client Launched", "SecureFileX Client has been launched")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch client: {e}")
    
    def launch_server(self):
        """Launch the GUI server"""
        try:
            subprocess.Popen([sys.executable, 'gui_server.py'])
            messagebox.showinfo("Server Launched", "SecureFileX Server has been launched")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to launch server: {e}")
    
    def show_cli_help(self):
        """Show CLI help"""
        help_text = """
Command Line Usage:

Server:
  python securefx.py server [--host HOST] [--port PORT]

Client:
  python securefx.py client [--host HOST] [--port PORT]
  python securefx.py client --upload FILE
  python securefx.py client --download FILE
  python securefx.py client --list

Configuration:
  python securefx.py config --show
  python securefx.py config --validate

User Management:
  python securefx.py user create USERNAME
  python securefx.py user list

For more information, see README.md
        """
        
        help_window = tk.Toplevel(self.root)
        help_window.title("CLI Help")
        help_window.geometry("500x400")
        help_window.transient(self.root)
        
        text_widget = tk.Text(help_window, wrap=tk.WORD, font=('Courier', 9))
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text_widget.insert(tk.END, help_text)
        text_widget.config(state=tk.DISABLED)
        
        ttk.Button(help_window, text="Close", 
                  command=help_window.destroy).pack(pady=10)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = SecureFileXLauncher(root)
    root.mainloop()


if __name__ == '__main__':
    main()
