# Contributing to SecureFileX

Thank you for your interest in contributing to SecureFileX! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Process](#development-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## Getting Started

1. **Fork the repository**
   ```bash
   git clone https://github.com/OussamaERrafif/SecureFileX.git
   cd SecureFileX
   ```

2. **Set up the development environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Create a new branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Process

### Project Structure

```
SecureFileX/
├── src/                    # Source code
│   ├── AESCipher.py       # AES encryption implementation
│   ├── KeyManager.py      # RSA and key management
│   ├── FileHandler.py     # File operations
│   ├── Authenticator.py   # Authentication system
│   ├── Logger.py          # Logging system
│   ├── Config.py          # Configuration management
│   ├── file_server.py     # Server implementation
│   ├── file_client.py     # Client implementation
│   └── tests/             # Test files
├── securefx.py            # CLI entry point
├── config.json            # Configuration file
└── requirements.txt       # Dependencies
```

### Making Changes

1. **Write clean, documented code**
   - Follow PEP 8 style guidelines
   - Add docstrings to all functions and classes
   - Use meaningful variable and function names

2. **Add tests for new features**
   - Write unit tests for new functionality
   - Ensure all tests pass before submitting
   - Aim for high test coverage

3. **Update documentation**
   - Update README.md if adding new features
   - Add inline comments for complex logic
   - Update docstrings for modified functions

## Coding Standards

### Python Style Guide

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) guidelines
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Use descriptive variable names

### Example

```python
def encrypt_file(file_path, encryption_key):
    """
    Encrypt a file using AES encryption.
    
    Args:
        file_path (str): Path to the file to encrypt
        encryption_key (bytes): AES encryption key
        
    Returns:
        bool: True if successful, False otherwise
        
    Raises:
        FileNotFoundError: If file_path doesn't exist
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # Implementation here
    return True
```

### Security Considerations

When contributing, please ensure:

- **No hardcoded credentials** - Use configuration files or environment variables
- **Input validation** - Sanitize all user inputs
- **Secure defaults** - Use secure configurations by default
- **Error handling** - Don't expose sensitive information in error messages
- **Cryptographic best practices** - Use established libraries and algorithms

## Testing

### Running Tests

Run all tests:
```bash
python -m unittest discover -s src/tests -p "test_*.py" -v
```

Run specific test file:
```bash
python -m unittest src.tests.test_AESCipher -v
```

### Writing Tests

Place tests in `src/tests/` directory:

```python
import unittest
from src.AESCipher import AESCipher

class TestAESCipher(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        self.key = os.urandom(32)
        self.cipher = AESCipher(self.key)
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption."""
        plaintext = b"Hello, World!"
        ciphertext = self.cipher.encrypt(plaintext)
        decrypted = self.cipher.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted)
```

## Submitting Changes

### Pull Request Process

1. **Ensure your code passes all tests**
   ```bash
   python -m unittest discover -s src/tests -p "test_*.py" -v
   ```

2. **Update documentation**
   - Update README.md if needed
   - Add docstrings to new functions
   - Update CHANGELOG if applicable

3. **Commit your changes**
   ```bash
   git add .
   git commit -m "Add feature: brief description"
   ```

4. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create a Pull Request**
   - Go to the original repository on GitHub
   - Click "New Pull Request"
   - Select your branch
   - Fill in the PR template with:
     - Description of changes
     - Related issue numbers
     - Testing performed
     - Screenshots (if applicable)

### PR Guidelines

- **One feature per PR** - Keep changes focused
- **Clear description** - Explain what and why
- **Link issues** - Reference related issues
- **Request review** - Tag maintainers for review

### Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Adding or updating tests
- `refactor`: Code refactoring
- `style`: Code style changes (formatting)
- `perf`: Performance improvements

Example:
```
feat: Add file download functionality

- Implemented download command in client
- Added download handler in server
- Updated CLI to support --download flag
- Added file integrity verification for downloads

Closes #123
```

## Feature Requests and Bug Reports

### Reporting Bugs

When reporting bugs, include:
- **Description** - Clear description of the issue
- **Steps to reproduce** - How to reproduce the bug
- **Expected behavior** - What should happen
- **Actual behavior** - What actually happens
- **Environment** - OS, Python version, etc.
- **Logs** - Relevant error messages or logs

### Requesting Features

When requesting features, include:
- **Use case** - Why is this feature needed?
- **Description** - What should the feature do?
- **Alternatives** - Any alternative solutions considered?
- **Additional context** - Screenshots, mockups, etc.

## Questions and Support

- **Issues** - For bug reports and feature requests
- **Discussions** - For general questions and ideas
- **Documentation** - Check README.md first

## License

By contributing to SecureFileX, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to SecureFileX! Your efforts help make secure file transfer accessible to everyone.
