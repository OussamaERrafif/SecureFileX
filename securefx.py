#!/usr/bin/env python3
"""
SecureFileX Command Line Interface
Main entry point for the SecureFileX secure file transfer system.
"""

import sys
import os
import argparse
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from Config import get_config
from Logger import get_logger


def run_server(args):
    """Run the SecureFileX server."""
    from src.file_server import SecureFileTransferServer
    
    config = get_config()
    logger = get_logger('CLI')
    
    # Validate configuration if requested
    if args.validate_config:
        errors = config.validate_config()
        if errors:
            print("Configuration errors found:")
            for error in errors:
                print(f"  - {error}")
            return 1
        else:
            print("Configuration is valid")
    
    # Override config with command line arguments
    host = args.host or config.server_config.host
    port = args.port or config.server_config.port
    upload_dir = args.upload_dir or config.server_config.upload_dir
    
    try:
        print(f"Starting SecureFileX Server...")
        logger.info("Starting SecureFileX Server")
        
        server = SecureFileTransferServer(host=host, port=port, upload_dir=upload_dir)
        server.start_server()
        
    except KeyboardInterrupt:
        print("\nServer shutdown by user")
        logger.info("Server shutdown by user")
    except Exception as e:
        print(f"Server error: {e}")
        logger.critical(f"Server error: {e}")
        return 1
    
    return 0


def run_client(args):
    """Run the SecureFileX client."""
    from src.file_client import SecureFileTransferClient
    
    config = get_config()
    logger = get_logger('CLI')
    
    # Override config with command line arguments
    host = args.host or config.client_config.default_host
    port = args.port or config.client_config.default_port
    
    try:
        print(f"Starting SecureFileX Client...")
        logger.info("Starting SecureFileX Client")
        
        client = SecureFileTransferClient(host=host, port=port)
        client.connect()
        
        # Handle specific file upload if provided
        if args.upload_file:
            success = client.upload_file(args.upload_file)
            client.disconnect()
            return 0 if success else 1
        # Handle specific file download if provided
        elif args.download_file:
            success = client.download_file(args.download_file)
            client.disconnect()
            return 0 if success else 1
        # Handle list files if provided
        elif args.list_files:
            client.list_files()
            client.disconnect()
            return 0
        else:
            # Interactive mode
            client.interactive_mode()
            client.disconnect()
        
    except Exception as e:
        print(f"Client error: {e}")
        logger.error(f"Client error: {e}")
        return 1
    
    return 0


def show_config(args):
    """Show current configuration."""
    config = get_config()
    config.print_config()
    
    if args.validate:
        errors = config.validate_config()
        if errors:
            print("\nConfiguration errors found:")
            for error in errors:
                print(f"  - {error}")
            return 1
        else:
            print("\nConfiguration is valid ✓")
    
    return 0


def create_user(args):
    """Create a new user."""
    from src.Authenticator import SimpleAuthenticator
    import getpass
    
    auth = SimpleAuthenticator()
    
    username = args.username
    if not username:
        username = input("Username: ")
    
    password = args.password
    if not password:
        password = getpass.getpass("Password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        if password != confirm_password:
            print("Passwords don't match")
            return 1
    
    success, message = auth.add_user(username, password)
    if success:
        print(f"✓ {message}")
        return 0
    else:
        print(f"✗ {message}")
        return 1


def list_users(args):
    """List all users."""
    from src.Authenticator import SimpleAuthenticator
    
    auth = SimpleAuthenticator()
    users = auth.list_users()
    
    if users:
        print("Registered users:")
        for user in users:
            print(f"  - {user}")
    else:
        print("No users found")
    
    return 0


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='SecureFileX - Secure File Transfer System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s server                          # Start server with default settings
  %(prog)s server --host 0.0.0.0 --port 8080  # Start server on all interfaces
  %(prog)s client                          # Start interactive client
  %(prog)s client --upload test.txt        # Upload a file and exit
  %(prog)s config --show                   # Show current configuration
  %(prog)s user --create admin             # Create a new user
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Server command
    server_parser = subparsers.add_parser('server', help='Start the SecureFileX server')
    server_parser.add_argument('--host', help='Server host address')
    server_parser.add_argument('--port', type=int, help='Server port number')
    server_parser.add_argument('--upload-dir', help='Upload directory path')
    server_parser.add_argument('--validate-config', action='store_true', 
                              help='Validate configuration before starting')
    
    # Client command
    client_parser = subparsers.add_parser('client', help='Start the SecureFileX client')
    client_parser.add_argument('--host', help='Server host address')
    client_parser.add_argument('--port', type=int, help='Server port number')
    client_parser.add_argument('--upload', dest='upload_file', 
                              help='Upload a file and exit (non-interactive)')
    client_parser.add_argument('--download', dest='download_file',
                              help='Download a file and exit (non-interactive)')
    client_parser.add_argument('--list', dest='list_files', action='store_true',
                              help='List available files and exit (non-interactive)')
    
    # Config command
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_parser.add_argument('--show', action='store_true', help='Show current configuration')
    config_parser.add_argument('--validate', action='store_true', help='Validate configuration')
    
    # User management command
    user_parser = subparsers.add_parser('user', help='User management')
    user_subparsers = user_parser.add_subparsers(dest='user_action', help='User actions')
    
    create_user_parser = user_subparsers.add_parser('create', help='Create a new user')
    create_user_parser.add_argument('username', nargs='?', help='Username')
    create_user_parser.add_argument('--password', help='Password (will prompt if not provided)')
    
    user_subparsers.add_parser('list', help='List all users')
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Execute command
    try:
        if args.command == 'server':
            return run_server(args)
        elif args.command == 'client':
            return run_client(args)
        elif args.command == 'config':
            return show_config(args)
        elif args.command == 'user':
            if args.user_action == 'create':
                return create_user(args)
            elif args.user_action == 'list':
                return list_users(args)
            else:
                user_parser.print_help()
                return 1
        else:
            parser.print_help()
            return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())