#!/usr/bin/env python3
"""
SecureFileX Demo Script
Demonstrates the key features of SecureFileX
"""

import os
import tempfile


def print_section(title):
    """Print a section header."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


def create_sample_files():
    """Create sample files for demonstration."""
    print_section("Creating Sample Files")
    
    # Create a temporary directory
    demo_dir = tempfile.mkdtemp(prefix='securefx_demo_')
    print(f"Demo directory: {demo_dir}")
    
    # Create sample files
    files = {
        'hello.txt': 'Hello from SecureFileX!',
        'data.txt': 'Sample data: ' + ('x' * 1000),
        'config.txt': 'Configuration example\nLine 2\nLine 3'
    }
    
    for filename, content in files.items():
        filepath = os.path.join(demo_dir, filename)
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"✓ Created: {filename} ({len(content)} bytes)")
    
    return demo_dir, list(files.keys())


def show_features():
    """Display SecureFileX features."""
    print_section("SecureFileX Features")
    
    features = [
        ("🔐 Security", [
            "End-to-End AES-256 encryption",
            "RSA-2048 key exchange",
            "SHA-256 file integrity verification",
            "Session-based authentication"
        ]),
        ("📁 File Transfer", [
            "Upload files to server",
            "Download files from server",
            "List available files",
            "Progress monitoring"
        ]),
        ("👤 User Management", [
            "Multi-user support",
            "Password hashing with salt",
            "Session token management",
            "User creation and listing"
        ]),
        ("⚙️ Configuration", [
            "JSON-based configuration",
            "Customizable settings",
            "Configuration validation",
            "Comprehensive logging"
        ])
    ]
    
    for category, items in features:
        print(f"{category}")
        for item in items:
            print(f"  • {item}")
        print()


def show_usage_examples():
    """Show usage examples."""
    print_section("Usage Examples")
    
    examples = [
        ("Start Server", "python securefx.py server"),
        ("Start Client", "python securefx.py client"),
        ("Upload File", "python securefx.py client --upload myfile.txt"),
        ("Download File", "python securefx.py client --download myfile.txt"),
        ("List Files", "python securefx.py client --list"),
        ("Create User", "python securefx.py user create username"),
        ("View Config", "python securefx.py config --show"),
    ]
    
    for description, command in examples:
        print(f"{description}:")
        print(f"  $ {command}")
        print()


def show_architecture():
    """Display architecture information."""
    print_section("Architecture")
    
    print("Client                    Server")
    print("  |                         |")
    print("  |--- RSA Public Key ----->|")
    print("  |<-- RSA Public Key ------|")
    print("  |                         |")
    print("  |-- Encrypted AES Key --->|")
    print("  |                         |")
    print("  |-- Authentication ------>|")
    print("  |<-- Session Token -------|")
    print("  |                         |")
    print("  |-- Encrypted Commands -->|")
    print("  |<-- Encrypted Responses -|")
    print()
    
    print("Encryption Process:")
    print("  1. RSA-2048 for secure AES key exchange")
    print("  2. AES-256-CBC for all data transfer")
    print("  3. SHA-256 hashing for file verification")
    print("  4. Salted password hashing with session tokens")
    print()


def show_getting_started():
    """Show getting started guide."""
    print_section("Getting Started")
    
    steps = [
        "1. Install dependencies:",
        "   pip install -r requirements.txt",
        "",
        "2. Start the server:",
        "   python securefx.py server",
        "",
        "3. In another terminal, start the client:",
        "   python securefx.py client",
        "",
        "4. Login with default credentials:",
        "   Username: admin",
        "   Password: admin123",
        "",
        "5. Try uploading a file:",
        "   SecureFileX> upload myfile.txt",
        "",
        "6. List available files:",
        "   SecureFileX> list",
        "",
        "7. Download a file:",
        "   SecureFileX> download myfile.txt",
    ]
    
    for step in steps:
        print(step)


def show_security_info():
    """Display security information."""
    print_section("Security Information")
    
    print("Cryptographic Standards:")
    print("  • AES-256-CBC for symmetric encryption")
    print("  • RSA-2048 for key exchange")
    print("  • SHA-256 for file integrity verification")
    print("  • Salted password hashing")
    print()
    
    print("Security Best Practices:")
    print("  ✓ Change default admin password")
    print("  ✓ Use strong passwords (min 6 characters)")
    print("  ✓ Protect configuration files")
    print("  ✓ Monitor security logs regularly")
    print("  ✓ Keep dependencies updated")
    print()


def main():
    """Main demo function."""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║                    SecureFileX Demo                       ║
    ║         Secure File Transfer with End-to-End Encryption   ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    show_features()
    show_architecture()
    show_security_info()
    show_usage_examples()
    show_getting_started()
    
    # Create sample files for testing
    demo_dir, files = create_sample_files()
    
    print_section("Next Steps")
    print(f"Sample files created in: {demo_dir}")
    print("\nYou can now test SecureFileX with these files:")
    for filename in files:
        filepath = os.path.join(demo_dir, filename)
        print(f"  python securefx.py client --upload {filepath}")
    
    print("\nFor more information:")
    print("  • README.md - Comprehensive documentation")
    print("  • EXAMPLES.md - Detailed usage examples")
    print("  • CONTRIBUTING.md - Contribution guidelines")
    print()
    
    print("Happy secure file transferring! 🔐")
    print()


if __name__ == '__main__':
    main()
