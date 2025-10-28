import unittest
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from Validator import (
    validate_filename, validate_file_path, validate_port,
    validate_host, validate_file_size, validate_username,
    validate_password, ValidationError
)


class TestValidator(unittest.TestCase):
    """Test suite for validation utilities."""
    
    def test_validate_filename_valid(self):
        """Test validating a valid filename."""
        filename = validate_filename("test.txt")
        self.assertEqual(filename, "test.txt")
    
    def test_validate_filename_with_path(self):
        """Test validating filename strips path."""
        filename = validate_filename("/path/to/test.txt")
        self.assertEqual(filename, "test.txt")
    
    def test_validate_filename_empty(self):
        """Test validating empty filename raises error."""
        with self.assertRaises(ValidationError):
            validate_filename("")
    
    def test_validate_filename_parent_dir(self):
        """Test validating filename with parent directory reference."""
        # After basename, "../test.txt" becomes "test.txt", which is valid
        # So we test a different case with .. in the filename itself
        filename = validate_filename("../test.txt")
        self.assertEqual(filename, "test.txt")
    
    def test_validate_filename_too_long(self):
        """Test validating filename that's too long."""
        long_name = "a" * 256
        with self.assertRaises(ValidationError):
            validate_filename(long_name)
    
    def test_validate_port_valid(self):
        """Test validating a valid port."""
        port = validate_port(8080)
        self.assertEqual(port, 8080)
    
    def test_validate_port_too_low(self):
        """Test validating port that's too low."""
        with self.assertRaises(ValidationError):
            validate_port(0)
    
    def test_validate_port_too_high(self):
        """Test validating port that's too high."""
        with self.assertRaises(ValidationError):
            validate_port(65536)
    
    def test_validate_port_not_int(self):
        """Test validating non-integer port."""
        with self.assertRaises(ValidationError):
            validate_port("8080")
    
    def test_validate_host_valid(self):
        """Test validating a valid host."""
        host = validate_host("localhost")
        self.assertEqual(host, "localhost")
    
    def test_validate_host_empty(self):
        """Test validating empty host."""
        with self.assertRaises(ValidationError):
            validate_host("")
    
    def test_validate_file_size_valid(self):
        """Test validating a valid file size."""
        size = validate_file_size(1024)
        self.assertEqual(size, 1024)
    
    def test_validate_file_size_negative(self):
        """Test validating negative file size."""
        with self.assertRaises(ValidationError):
            validate_file_size(-1)
    
    def test_validate_file_size_exceeds_max(self):
        """Test validating file size that exceeds maximum."""
        with self.assertRaises(ValidationError):
            validate_file_size(2048, max_size=1024)
    
    def test_validate_username_valid(self):
        """Test validating a valid username."""
        username = validate_username("user123")
        self.assertEqual(username, "user123")
    
    def test_validate_username_too_short(self):
        """Test validating username that's too short."""
        with self.assertRaises(ValidationError):
            validate_username("ab")
    
    def test_validate_username_invalid_chars(self):
        """Test validating username with invalid characters."""
        with self.assertRaises(ValidationError):
            validate_username("user@123")
    
    def test_validate_password_valid(self):
        """Test validating a valid password."""
        password = validate_password("password123")
        self.assertEqual(password, "password123")
    
    def test_validate_password_too_short(self):
        """Test validating password that's too short."""
        with self.assertRaises(ValidationError):
            validate_password("123")


if __name__ == '__main__':
    unittest.main()
