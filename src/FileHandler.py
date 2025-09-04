import os
import hashlib
from pathlib import Path


class FileHandler:
    """
    FileHandler class for secure file operations including integrity verification.
    
    Methods:
        read_file_chunks: Read a file in chunks for memory-efficient processing.
        write_file_chunks: Write chunks to a file.
        calculate_file_hash: Calculate SHA-256 hash of a file for integrity verification.
        verify_file_integrity: Verify file integrity using SHA-256 hash.
    """
    
    @staticmethod
    def read_file_chunks(file_path, chunk_size=8192):
        """
        Read a file in chunks for memory-efficient processing.
        
        Args:
            file_path (str): Path to the file to read.
            chunk_size (int): Size of each chunk in bytes.
            
        Yields:
            bytes: File chunk.
            
        Raises:
            FileNotFoundError: If the file doesn't exist.
            IOError: If there's an error reading the file.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
            
        try:
            with open(file_path, 'rb') as file:
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    yield chunk
        except IOError as e:
            raise IOError(f"Error reading file {file_path}: {e}")
    
    @staticmethod
    def write_file_chunks(file_path, chunks):
        """
        Write chunks to a file.
        
        Args:
            file_path (str): Path where the file should be written.
            chunks (iterable): Iterable of byte chunks to write.
            
        Raises:
            IOError: If there's an error writing the file.
        """
        try:
            # Create directory if it doesn't exist
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'wb') as file:
                for chunk in chunks:
                    file.write(chunk)
        except IOError as e:
            raise IOError(f"Error writing file {file_path}: {e}")
    
    @staticmethod
    def calculate_file_hash(file_path):
        """
        Calculate SHA-256 hash of a file for integrity verification.
        
        Args:
            file_path (str): Path to the file.
            
        Returns:
            str: Hexadecimal SHA-256 hash of the file.
            
        Raises:
            FileNotFoundError: If the file doesn't exist.
            IOError: If there's an error reading the file.
        """
        sha256_hash = hashlib.sha256()
        
        for chunk in FileHandler.read_file_chunks(file_path):
            sha256_hash.update(chunk)
            
        return sha256_hash.hexdigest()
    
    @staticmethod
    def verify_file_integrity(file_path, expected_hash):
        """
        Verify file integrity using SHA-256 hash.
        
        Args:
            file_path (str): Path to the file to verify.
            expected_hash (str): Expected SHA-256 hash.
            
        Returns:
            bool: True if file integrity is verified, False otherwise.
        """
        try:
            actual_hash = FileHandler.calculate_file_hash(file_path)
            return actual_hash.lower() == expected_hash.lower()
        except (FileNotFoundError, IOError):
            return False
    
    @staticmethod
    def get_file_size(file_path):
        """
        Get the size of a file in bytes.
        
        Args:
            file_path (str): Path to the file.
            
        Returns:
            int: File size in bytes.
            
        Raises:
            FileNotFoundError: If the file doesn't exist.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        return os.path.getsize(file_path)