# SecureFileX

## Project Overview

SecureFileX is a comprehensive secure file transfer system designed to ensure the confidentiality, integrity, and authenticity of files being transferred over a network. Leveraging robust cryptographic techniques and secure coding practices, this project demonstrates proficiency in cybersecurity, cryptography, and network programming.

## Key Features

### 🔐 Security Features
- **End-to-End Encryption**: AES-256 encryption for file contents with RSA key exchange
- **File Integrity Verification**: SHA-256 hash verification for all transfers
- **User Authentication**: Session-based authentication with secure password hashing
- **Secure Communication**: All network traffic is encrypted using hybrid cryptography

### 📁 File Transfer
- **Chunked Transfer**: Memory-efficient file transfer with progress monitoring
- **Large File Support**: Configurable file size limits (default: 100MB)
- **Upload & Download**: Full bidirectional file transfer support
- **File Listing**: Browse available files on the server
- **Integrity Checking**: Automatic verification of file integrity after transfer
- **Safe File Handling**: Secure file path validation and sanitization

### 👤 User Management
- **Multi-user Support**: Username/password authentication system
- **Session Management**: Token-based sessions with configurable timeout
- **Security Logging**: Comprehensive logging of security events

### ⚙️ Configuration & Management
- **Configurable Settings**: JSON-based configuration for all components
- **Comprehensive Logging**: Multi-level logging with file rotation
- **CLI Interface**: Command-line interface for easy operation
- **GUI Applications**: User-friendly graphical interfaces for client and server
- **Validation**: Configuration validation and error checking

## Documentation

- **[README.md](README.md)** - Main documentation (you are here)
- **[GUI_README.md](GUI_README.md)** - GUI applications documentation and usage
- **[EXAMPLES.md](EXAMPLES.md)** - Detailed usage examples and tutorials
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and changes
- **[LICENSE](LICENSE)** - MIT License

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/OussamaERrafif/SecureFileX.git
   cd SecureFileX
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Quick Start Demo

Run the demo script to see all features:
```bash
python demo.py
```

This will display feature overview, create sample files, and show usage examples.

### Graphical User Interface (GUI)

SecureFileX now includes user-friendly GUI applications:

**Launch the unified GUI launcher:**
```bash
python gui_launcher.py
```

**Or launch directly:**
```bash
# Start GUI Client
python gui_client.py

# Start GUI Server
python gui_server.py
```

**Note:** GUI applications require tkinter. On Linux, install with:
```bash
sudo apt-get install python3-tk
```

See [GUI_README.md](GUI_README.md) for detailed GUI documentation.

### Quick Start (CLI)

**Start the server:**
```bash
python securefx.py server
```

**Connect with client:**
```bash
python securefx.py client
```

Default credentials: `admin` / `admin123`

### Command Line Interface

SecureFileX provides a comprehensive CLI for all operations:

**Server Operations:**
```bash
# Start server with default settings
python securefx.py server

# Start server on specific host/port
python securefx.py server --host 0.0.0.0 --port 8080

# Validate configuration before starting
python securefx.py server --validate-config
```

**Client Operations:**
```bash
# Interactive client mode
python securefx.py client

# Upload a file directly
python securefx.py client --upload myfile.txt

# Download a file directly
python securefx.py client --download myfile.txt

# List available files
python securefx.py client --list

# Connect to specific server
python securefx.py client --host 192.168.1.100 --port 8080
```

**Configuration Management:**
```bash
# Show current configuration
python securefx.py config --show

# Validate configuration
python securefx.py config --validate
```

**User Management:**
```bash
# Create new user
python securefx.py user create newuser

# List all users
python securefx.py user list
```

### Interactive Client Commands

In interactive mode, the client supports these commands:
- `upload <file_path>` - Upload a file to the server
- `download <filename>` - Download a file from the server
- `list` - List all available files on the server
- `message <text>` - Send a text message to the server
- `quit` - Exit the client

## Architecture

### Core Components

1. **AESCipher.py**: AES encryption/decryption with CBC mode
2. **KeyManager.py**: RSA key generation and symmetric key management
3. **FileHandler.py**: Secure file operations with integrity verification
4. **Authenticator.py**: User authentication and session management
5. **Logger.py**: Comprehensive logging system
6. **Config.py**: Configuration management
7. **file_server.py**: Secure file transfer server
8. **file_client.py**: Secure file transfer client
9. **securefx.py**: Command-line interface

### Security Architecture

```
Client                    Server
  |                         |
  |--- RSA Public Key ----->|
  |<-- RSA Public Key ------|
  |                         |
  |-- Encrypted AES Key --->|
  |                         |
  |-- Authentication ------>|
  |<-- Session Token -------|
  |                         |
  |-- Encrypted Commands -->|
  |<-- Encrypted Responses -|
```

### Encryption Process

1. **Key Exchange**: RSA-2048 for secure AES key exchange
2. **Symmetric Encryption**: AES-256-CBC for all data transfer
3. **Integrity**: SHA-256 hashing for file verification
4. **Authentication**: Salted password hashing with session tokens

## Configuration

The system uses a JSON configuration file (`config.json`) with three main sections:

```json
{
  "server": {
    "host": "localhost",
    "port": 12345,
    "upload_dir": "uploads",
    "max_file_size": 104857600,
    "session_timeout": 3600,
    "max_connections": 10,
    "log_level": "INFO",
    "require_authentication": true
  },
  "client": {
    "default_host": "localhost",
    "default_port": 12345,
    "chunk_size": 8192,
    "connection_timeout": 30,
    "retry_attempts": 3,
    "log_level": "INFO"
  },
  "security": {
    "rsa_key_size": 2048,
    "aes_key_size": 32,
    "password_min_length": 6,
    "max_login_attempts": 3,
    "lockout_duration": 300,
    "hash_algorithm": "sha256"
  }
}
```

## Logging

The system provides comprehensive logging with multiple levels:

- **Application Logs**: `logs/server.log`, `logs/client.log`
- **Security Events**: `logs/security.log`
- **CLI Operations**: `logs/cli.log`

Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL

## Testing

Run the test suite:
```bash
python -m unittest src.tests.test_AESCipher src.tests.test_KeyManager src.tests.test_FileHandler -v
```

All tests include:
- AES encryption/decryption validation
- RSA key management verification
- File integrity and hash verification
- Error handling and edge cases

## Security Considerations

- **Encryption**: Uses industry-standard AES-256 and RSA-2048
- **Key Management**: Secure key generation and exchange
- **Authentication**: Salted password hashing with session management
- **File Validation**: SHA-256 integrity verification
- **Secure Coding**: Input validation, path sanitization, error handling
- **Logging**: Comprehensive security event logging

## Dependencies

- Python 3.7+
- cryptography==42.0.8
- cffi==1.16.0
- pycparser==2.22

## Contributing

1. Fork the repository
2. Create a new branch (`git checkout -b feature-branch`)
3. Make your changes
4. Run tests to ensure functionality
5. Commit your changes (`git commit -am 'Add new feature'`)
6. Push to the branch (`git push origin feature-branch`)
7. Create a new Pull Request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [cryptography](https://cryptography.io/en/latest/) library for providing robust cryptographic tools
- Community and contributors for their support and contributions

## Future Enhancements

- ~~File download functionality~~ ✓ Implemented
- ~~GUI applications~~ ✓ Implemented
- Multi-threaded server support
- Full drag-and-drop support in GUI (with tkinterdnd2)
- Web-based user interface
- Database integration for user management
- File compression before encryption
- Rate limiting and DDoS protection
- File versioning and metadata
- Automated file cleanup policies
- Bandwidth monitoring and throttling
- Multi-file batch operations