"""
Validation utilities for SecureFileX.
Provides input validation and sanitization functions.
"""

import os
import re


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


def validate_filename(filename):
    """
    Validate and sanitize a filename.
    
    Args:
        filename (str): Filename to validate
        
    Returns:
        str: Sanitized filename
        
    Raises:
        ValidationError: If filename is invalid
    """
    if not filename:
        raise ValidationError("Filename cannot be empty")
    
    # Remove any path components
    filename = os.path.basename(filename)
    
    # Check for dangerous patterns
    dangerous_patterns = [
        r'\.\.',  # Parent directory
        r'[<>:"|?*]',  # Windows invalid chars
        r'[\x00-\x1f]',  # Control characters
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, filename):
            raise ValidationError(f"Filename contains invalid characters: {filename}")
    
    # Check filename length
    if len(filename) > 255:
        raise ValidationError("Filename too long (max 255 characters)")
    
    return filename


def validate_file_path(file_path, must_exist=True):
    """
    Validate a file path.
    
    Args:
        file_path (str): File path to validate
        must_exist (bool): Whether the file must exist
        
    Returns:
        str: Validated file path
        
    Raises:
        ValidationError: If path is invalid
    """
    if not file_path:
        raise ValidationError("File path cannot be empty")
    
    # Check if file exists when required
    if must_exist and not os.path.exists(file_path):
        raise ValidationError(f"File not found: {file_path}")
    
    # Check if it's actually a file
    if must_exist and not os.path.isfile(file_path):
        raise ValidationError(f"Path is not a file: {file_path}")
    
    return os.path.abspath(file_path)


def validate_port(port):
    """
    Validate a network port number.
    
    Args:
        port (int): Port number to validate
        
    Returns:
        int: Validated port number
        
    Raises:
        ValidationError: If port is invalid
    """
    if not isinstance(port, int):
        raise ValidationError("Port must be an integer")
    
    if port < 1 or port > 65535:
        raise ValidationError("Port must be between 1 and 65535")
    
    # Check for privileged ports
    if port < 1024:
        import warnings
        warnings.warn("Using privileged port (< 1024) may require elevated permissions")
    
    return port


def validate_host(host):
    """
    Validate a hostname or IP address.
    
    Args:
        host (str): Hostname or IP address to validate
        
    Returns:
        str: Validated host
        
    Raises:
        ValidationError: If host is invalid
    """
    if not host:
        raise ValidationError("Host cannot be empty")
    
    # Basic validation - allow hostnames and IP addresses
    if not isinstance(host, str):
        raise ValidationError("Host must be a string")
    
    # Check length
    if len(host) > 253:
        raise ValidationError("Hostname too long (max 253 characters)")
    
    return host


def validate_file_size(file_size, max_size=None):
    """
    Validate file size.
    
    Args:
        file_size (int): File size in bytes
        max_size (int, optional): Maximum allowed size
        
    Returns:
        int: Validated file size
        
    Raises:
        ValidationError: If file size is invalid
    """
    if not isinstance(file_size, int):
        raise ValidationError("File size must be an integer")
    
    if file_size < 0:
        raise ValidationError("File size cannot be negative")
    
    if max_size is not None and file_size > max_size:
        raise ValidationError(f"File size ({file_size} bytes) exceeds maximum ({max_size} bytes)")
    
    return file_size


def validate_username(username):
    """
    Validate a username.
    
    Args:
        username (str): Username to validate
        
    Returns:
        str: Validated username
        
    Raises:
        ValidationError: If username is invalid
    """
    if not username:
        raise ValidationError("Username cannot be empty")
    
    if not isinstance(username, str):
        raise ValidationError("Username must be a string")
    
    # Check length
    if len(username) < 3:
        raise ValidationError("Username must be at least 3 characters")
    
    if len(username) > 32:
        raise ValidationError("Username too long (max 32 characters)")
    
    # Check for valid characters (alphanumeric, underscore, hyphen)
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        raise ValidationError("Username can only contain letters, numbers, underscore, and hyphen")
    
    return username


def validate_password(password, min_length=6):
    """
    Validate a password.
    
    Args:
        password (str): Password to validate
        min_length (int): Minimum password length
        
    Returns:
        str: Validated password
        
    Raises:
        ValidationError: If password is invalid
    """
    if not password:
        raise ValidationError("Password cannot be empty")
    
    if not isinstance(password, str):
        raise ValidationError("Password must be a string")
    
    if len(password) < min_length:
        raise ValidationError(f"Password must be at least {min_length} characters")
    
    return password
