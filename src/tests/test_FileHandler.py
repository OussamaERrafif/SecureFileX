import os
import tempfile
import unittest
from src.FileHandler import FileHandler


class FileHandlerTests(unittest.TestCase):
    """Tests for FileHandler class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, 'test_file.txt')
        self.test_content = b'This is a test file for SecureFileX'
        
        # Create a test file
        with open(self.test_file, 'wb') as f:
            f.write(self.test_content)
    
    def tearDown(self):
        """Clean up test fixtures."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)
        if os.path.exists(self.test_dir):
            os.rmdir(self.test_dir)
    
    def test_read_file_chunks(self):
        """Test reading file in chunks."""
        chunks = list(FileHandler.read_file_chunks(self.test_file, chunk_size=10))
        reconstructed = b''.join(chunks)
        self.assertEqual(reconstructed, self.test_content)
    
    def test_read_nonexistent_file(self):
        """Test reading a nonexistent file."""
        with self.assertRaises(FileNotFoundError):
            list(FileHandler.read_file_chunks('nonexistent_file.txt'))
    
    def test_write_file_chunks(self):
        """Test writing file chunks."""
        output_file = os.path.join(self.test_dir, 'output_test.txt')
        chunks = [b'Hello', b' ', b'World', b'!']
        
        FileHandler.write_file_chunks(output_file, chunks)
        
        with open(output_file, 'rb') as f:
            content = f.read()
        
        self.assertEqual(content, b'Hello World!')
        os.remove(output_file)
    
    def test_calculate_file_hash(self):
        """Test calculating file hash."""
        file_hash = FileHandler.calculate_file_hash(self.test_file)
        
        # Verify it's a valid SHA-256 hash (64 hex characters)
        self.assertEqual(len(file_hash), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in file_hash.lower()))
        
        # Calculate hash again to ensure consistency
        file_hash2 = FileHandler.calculate_file_hash(self.test_file)
        self.assertEqual(file_hash, file_hash2)
    
    def test_verify_file_integrity(self):
        """Test file integrity verification."""
        correct_hash = FileHandler.calculate_file_hash(self.test_file)
        wrong_hash = 'a' * 64  # Invalid hash
        
        # Test with correct hash
        self.assertTrue(FileHandler.verify_file_integrity(self.test_file, correct_hash))
        
        # Test with wrong hash
        self.assertFalse(FileHandler.verify_file_integrity(self.test_file, wrong_hash))
        
        # Test with nonexistent file
        self.assertFalse(FileHandler.verify_file_integrity('nonexistent.txt', correct_hash))
    
    def test_get_file_size(self):
        """Test getting file size."""
        expected_size = len(self.test_content)
        actual_size = FileHandler.get_file_size(self.test_file)
        self.assertEqual(actual_size, expected_size)
    
    def test_get_nonexistent_file_size(self):
        """Test getting size of nonexistent file."""
        with self.assertRaises(FileNotFoundError):
            FileHandler.get_file_size('nonexistent_file.txt')


if __name__ == "__main__":
    unittest.main()