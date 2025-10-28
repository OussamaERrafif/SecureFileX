#!/usr/bin/env python3
"""
SecureFileX Quick Start Script
Easy setup and launch script for SecureFileX
"""

import os
import sys
import subprocess
from pathlib import Path


def print_banner():
    """Print welcome banner"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║                    SecureFileX                            ║
    ║         Secure File Transfer with End-to-End Encryption   ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)


def check_dependencies():
    """Check if required dependencies are installed"""
    print("Checking dependencies...")
    
    try:
        import cryptography
        print("  ✓ cryptography installed")
    except ImportError:
        print("  ✗ cryptography not installed")
        return False
    
    try:
        import cffi
        print("  ✓ cffi installed")
    except ImportError:
        print("  ✗ cffi not installed")
        return False
    
    return True


def install_dependencies():
    """Install required dependencies"""
    print("\nInstalling dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✓ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("✗ Failed to install dependencies")
        return False


def check_tkinter():
    """Check if tkinter is available"""
    try:
        import tkinter
        return True
    except ImportError:
        return False


def create_directories():
    """Create necessary directories"""
    print("\nCreating directories...")
    
    dirs = ['uploads', 'logs', 'backups']
    for dir_name in dirs:
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
            print(f"  ✓ Created {dir_name}/")
        else:
            print(f"  ✓ {dir_name}/ exists")
    
    return True


def create_default_user():
    """Create default admin user if it doesn't exist"""
    print("\nChecking default user...")
    
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
    
    try:
        from Authenticator import SimpleAuthenticator
        auth = SimpleAuthenticator()
        users = auth.list_users()
        
        if 'admin' not in users:
            print("  Creating default admin user...")
            success, message = auth.add_user('admin', 'admin123')
            if success:
                print(f"  ✓ {message}")
                print("  ⚠️  Remember to change the default password!")
            else:
                print(f"  ✗ {message}")
        else:
            print("  ✓ Admin user exists")
        
        return True
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False


def show_menu():
    """Show main menu"""
    print("\n" + "=" * 60)
    print("What would you like to do?")
    print("=" * 60)
    print("1. Launch GUI Launcher (Client & Server)")
    print("2. Start Server (CLI)")
    print("3. Start Client (CLI)")
    print("4. Run Demo")
    print("5. View Configuration")
    print("6. Create User")
    print("7. File Manager")
    print("8. Backup Manager")
    print("9. Exit")
    print("=" * 60)


def main():
    """Main entry point"""
    print_banner()
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("Error: Python 3.7 or higher is required")
        sys.exit(1)
    
    print(f"Python version: {sys.version.split()[0]} ✓")
    
    # Check dependencies
    if not check_dependencies():
        print("\nDependencies missing. Install now? (yes/no): ", end='')
        if input().lower() == 'yes':
            if not install_dependencies():
                print("\nPlease install dependencies manually:")
                print("  pip install -r requirements.txt")
                sys.exit(1)
        else:
            print("\nPlease install dependencies manually:")
            print("  pip install -r requirements.txt")
            sys.exit(1)
    
    # Check tkinter for GUI
    has_tkinter = check_tkinter()
    if has_tkinter:
        print("  ✓ tkinter available (GUI enabled)")
    else:
        print("  ⚠️  tkinter not available (GUI disabled)")
        print("     Install tkinter for GUI support:")
        print("     Linux: sudo apt-get install python3-tk")
    
    # Setup
    create_directories()
    create_default_user()
    
    print("\n✓ Setup complete!")
    
    # Main loop
    while True:
        show_menu()
        choice = input("\nEnter choice (1-9): ").strip()
        
        if choice == '1':
            if has_tkinter:
                print("\nLaunching GUI Launcher...")
                subprocess.run([sys.executable, 'gui_launcher.py'])
            else:
                print("\n✗ GUI not available (tkinter not installed)")
        
        elif choice == '2':
            print("\nStarting Server...")
            print("Press Ctrl+C to stop\n")
            try:
                subprocess.run([sys.executable, 'securefx.py', 'server'])
            except KeyboardInterrupt:
                print("\n\nServer stopped")
        
        elif choice == '3':
            print("\nStarting Client...")
            subprocess.run([sys.executable, 'securefx.py', 'client'])
        
        elif choice == '4':
            print("\nRunning Demo...")
            subprocess.run([sys.executable, 'demo.py'])
        
        elif choice == '5':
            print("\nViewing Configuration...")
            subprocess.run([sys.executable, 'securefx.py', 'config', '--show'])
        
        elif choice == '6':
            print("\nCreate User")
            username = input("Username: ")
            subprocess.run([sys.executable, 'securefx.py', 'user', 'create', username])
        
        elif choice == '7':
            print("\nFile Manager - Available commands:")
            print("  --list              List files")
            print("  --stats             Show statistics")
            print("  --verify            Verify integrity")
            print("  --search PATTERN    Search files")
            print("  --clean DAYS        Clean old files")
            subprocess.run([sys.executable, 'file_manager.py', '--list'])
        
        elif choice == '8':
            print("\nBackup Manager - Available commands:")
            print("  --backup [NAME]     Create backup")
            print("  --restore NAME      Restore backup")
            print("  --list              List backups")
            subprocess.run([sys.executable, 'backup_manager.py', '--list'])
        
        elif choice == '9':
            print("\nGoodbye! 👋")
            break
        
        else:
            print("\n✗ Invalid choice. Please enter 1-9.")
        
        input("\nPress Enter to continue...")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nExiting... Goodbye! 👋")
        sys.exit(0)
