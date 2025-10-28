import unittest
import os
import sys
import tempfile
import shutil

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from file_client import SecureFileTransferClient


class TestFileClientDownload(unittest.TestCase):
    """Test suite for file client download functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, 'test_download.txt')
        with open(self.test_file, 'w') as f:
            f.write('Test content for download')
    
    def tearDown(self):
        """Clean up test files."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_format_size_bytes(self):
        """Test file size formatting in bytes."""
        client = SecureFileTransferClient()
        size_str = client._format_size(500)
        self.assertIn('B', size_str)
        self.assertIn('500', size_str)
    
    def test_format_size_kb(self):
        """Test file size formatting in KB."""
        client = SecureFileTransferClient()
        size_str = client._format_size(2048)
        self.assertIn('KB', size_str)
    
    def test_format_size_mb(self):
        """Test file size formatting in MB."""
        client = SecureFileTransferClient()
        size_str = client._format_size(5242880)
        self.assertIn('MB', size_str)
    
    def test_format_size_gb(self):
        """Test file size formatting in GB."""
        client = SecureFileTransferClient()
        size_str = client._format_size(2147483648)
        self.assertIn('GB', size_str)


if __name__ == '__main__':
    unittest.main()
