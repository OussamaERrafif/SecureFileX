#!/usr/bin/env python3
"""
SecureFileX File Manager Utility
Provides additional file management features for the upload directory
"""

import os
import sys
from pathlib import Path
from datetime import datetime
import hashlib

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from Config import get_config
from FileHandler import FileHandler


class FileManager:
    """Utility for managing files in the upload directory"""
    
    def __init__(self, upload_dir=None):
        self.config = get_config()
        self.upload_dir = upload_dir or self.config.server_config.upload_dir
        
        # Create upload directory if it doesn't exist
        if not os.path.exists(self.upload_dir):
            os.makedirs(self.upload_dir)
    
    def list_files(self, detailed=False):
        """List all files in the upload directory"""
        if not os.path.exists(self.upload_dir):
            print(f"Upload directory does not exist: {self.upload_dir}")
            return []
        
        files = []
        for filename in os.listdir(self.upload_dir):
            filepath = os.path.join(self.upload_dir, filename)
            if os.path.isfile(filepath):
                file_info = {
                    'filename': filename,
                    'size': os.path.getsize(filepath),
                    'modified': datetime.fromtimestamp(os.path.getmtime(filepath)),
                }
                if detailed:
                    file_info['hash'] = FileHandler.calculate_file_hash(filepath)
                files.append(file_info)
        
        return files
    
    def print_file_list(self, detailed=False):
        """Print formatted file list"""
        files = self.list_files(detailed=detailed)
        
        if not files:
            print("No files in upload directory")
            return
        
        print(f"\nFiles in {self.upload_dir}:")
        print(f"{'Filename':<40} {'Size':<15} {'Modified':<20}", end='')
        if detailed:
            print(f" {'Hash':<64}")
        else:
            print()
        print("-" * (75 + (64 if detailed else 0)))
        
        for file_info in sorted(files, key=lambda x: x['filename']):
            size_str = self._format_size(file_info['size'])
            modified_str = file_info['modified'].strftime('%Y-%m-%d %H:%M:%S')
            print(f"{file_info['filename']:<40} {size_str:<15} {modified_str:<20}", end='')
            if detailed:
                print(f" {file_info['hash']:<64}")
            else:
                print()
        
        total_size = sum(f['size'] for f in files)
        print(f"\nTotal: {len(files)} files, {self._format_size(total_size)}")
    
    def get_statistics(self):
        """Get statistics about files in upload directory"""
        files = self.list_files()
        
        if not files:
            return {
                'count': 0,
                'total_size': 0,
                'average_size': 0,
                'largest_file': None,
                'smallest_file': None,
            }
        
        sizes = [f['size'] for f in files]
        
        stats = {
            'count': len(files),
            'total_size': sum(sizes),
            'average_size': sum(sizes) // len(sizes),
            'largest_file': max(files, key=lambda x: x['size']),
            'smallest_file': min(files, key=lambda x: x['size']),
        }
        
        return stats
    
    def print_statistics(self):
        """Print formatted statistics"""
        stats = self.get_statistics()
        
        if stats['count'] == 0:
            print("No files in upload directory")
            return
        
        print("\n=== Upload Directory Statistics ===")
        print(f"Total Files: {stats['count']}")
        print(f"Total Size: {self._format_size(stats['total_size'])}")
        print(f"Average Size: {self._format_size(stats['average_size'])}")
        print(f"\nLargest File: {stats['largest_file']['filename']}")
        print(f"  Size: {self._format_size(stats['largest_file']['size'])}")
        print(f"\nSmallest File: {stats['smallest_file']['filename']}")
        print(f"  Size: {self._format_size(stats['smallest_file']['size'])}")
    
    def verify_integrity(self, filename=None):
        """Verify file integrity using stored hashes"""
        print("\n=== File Integrity Check ===")
        
        files = self.list_files(detailed=True)
        
        if filename:
            files = [f for f in files if f['filename'] == filename]
            if not files:
                print(f"File not found: {filename}")
                return
        
        for file_info in files:
            filepath = os.path.join(self.upload_dir, file_info['filename'])
            current_hash = FileHandler.calculate_file_hash(filepath)
            
            print(f"\n{file_info['filename']}:")
            print(f"  Hash: {current_hash}")
            print(f"  Size: {self._format_size(file_info['size'])}")
            print(f"  Status: ✓ Valid")
    
    def clean_old_files(self, days=30, dry_run=True):
        """Remove files older than specified days"""
        import time
        
        files = self.list_files()
        now = time.time()
        old_files = []
        
        for file_info in files:
            filepath = os.path.join(self.upload_dir, file_info['filename'])
            file_age_days = (now - os.path.getmtime(filepath)) / 86400
            
            if file_age_days > days:
                old_files.append({
                    'filename': file_info['filename'],
                    'age_days': int(file_age_days),
                    'size': file_info['size']
                })
        
        if not old_files:
            print(f"No files older than {days} days found")
            return
        
        print(f"\n{'DRY RUN - ' if dry_run else ''}Files older than {days} days:")
        for file_info in old_files:
            print(f"  {file_info['filename']} ({file_info['age_days']} days old, {self._format_size(file_info['size'])})")
        
        total_size = sum(f['size'] for f in old_files)
        print(f"\nTotal: {len(old_files)} files, {self._format_size(total_size)}")
        
        if not dry_run:
            confirm = input("\nDelete these files? (yes/no): ")
            if confirm.lower() == 'yes':
                for file_info in old_files:
                    filepath = os.path.join(self.upload_dir, file_info['filename'])
                    os.remove(filepath)
                    print(f"✓ Deleted: {file_info['filename']}")
                print(f"\n✓ Deleted {len(old_files)} files")
            else:
                print("Operation cancelled")
    
    def search_files(self, pattern):
        """Search for files matching pattern"""
        import fnmatch
        
        files = self.list_files()
        matches = [f for f in files if fnmatch.fnmatch(f['filename'].lower(), pattern.lower())]
        
        if not matches:
            print(f"No files matching '{pattern}' found")
            return
        
        print(f"\nFiles matching '{pattern}':")
        for file_info in matches:
            print(f"  {file_info['filename']} ({self._format_size(file_info['size'])})")
        
        print(f"\nTotal: {len(matches)} files")
    
    def _format_size(self, size):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='SecureFileX File Manager Utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list                    # List all files
  %(prog)s --list --detailed         # List files with hashes
  %(prog)s --stats                   # Show statistics
  %(prog)s --verify                  # Verify all files
  %(prog)s --verify file.txt         # Verify specific file
  %(prog)s --search "*.txt"          # Search for .txt files
  %(prog)s --clean 30 --dry-run      # Show files older than 30 days
  %(prog)s --clean 30                # Delete files older than 30 days
        """
    )
    
    parser.add_argument('--upload-dir', help='Upload directory path')
    parser.add_argument('--list', action='store_true', help='List all files')
    parser.add_argument('--detailed', action='store_true', help='Show detailed information')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--verify', nargs='?', const='', help='Verify file integrity')
    parser.add_argument('--search', metavar='PATTERN', help='Search for files')
    parser.add_argument('--clean', type=int, metavar='DAYS', help='Clean files older than DAYS')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be deleted (with --clean)')
    
    args = parser.parse_args()
    
    # Create file manager
    fm = FileManager(upload_dir=args.upload_dir)
    
    # Execute commands
    if args.list:
        fm.print_file_list(detailed=args.detailed)
    elif args.stats:
        fm.print_statistics()
    elif args.verify is not None:
        fm.verify_integrity(filename=args.verify if args.verify else None)
    elif args.search:
        fm.search_files(args.search)
    elif args.clean:
        fm.clean_old_files(days=args.clean, dry_run=args.dry_run)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
