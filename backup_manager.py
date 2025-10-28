#!/usr/bin/env python3
"""
SecureFileX Backup and Restore Utility
Provides backup and restore functionality for upload directory
"""

import os
import sys
import json
import shutil
import tarfile
from pathlib import Path
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from Config import get_config
from FileHandler import FileHandler


class BackupManager:
    """Manages backup and restore operations for SecureFileX"""
    
    def __init__(self, upload_dir=None, backup_dir='backups'):
        self.config = get_config()
        self.upload_dir = upload_dir or self.config.server_config.upload_dir
        self.backup_dir = backup_dir
        
        # Create backup directory if it doesn't exist
        if not os.path.exists(self.backup_dir):
            os.makedirs(self.backup_dir)
    
    def create_backup(self, backup_name=None):
        """Create a backup of the upload directory"""
        if not os.path.exists(self.upload_dir):
            print(f"Error: Upload directory does not exist: {self.upload_dir}")
            return None
        
        # Generate backup name if not provided
        if not backup_name:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"securefx_backup_{timestamp}"
        
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.tar.gz")
        
        print(f"Creating backup: {backup_name}")
        print(f"Source: {self.upload_dir}")
        print(f"Destination: {backup_path}")
        
        try:
            # Create manifest
            manifest = self._create_manifest()
            
            # Create tar.gz archive
            with tarfile.open(backup_path, "w:gz") as tar:
                # Add manifest directly to archive
                import io
                manifest_json = json.dumps(manifest, indent=2).encode('utf-8')
                manifest_info = tarfile.TarInfo(name='manifest.json')
                manifest_info.size = len(manifest_json)
                tar.addfile(manifest_info, io.BytesIO(manifest_json))
                
                # Add all files from upload directory
                for filename in os.listdir(self.upload_dir):
                    filepath = os.path.join(self.upload_dir, filename)
                    if os.path.isfile(filepath):
                        tar.add(filepath, arcname=filename)
                        print(f"  ✓ Added: {filename}")
            
            backup_size = os.path.getsize(backup_path)
            print(f"\n✓ Backup created successfully")
            print(f"  Size: {self._format_size(backup_size)}")
            print(f"  Files: {manifest['file_count']}")
            
            return backup_path
            
        except Exception as e:
            print(f"Error creating backup: {e}")
            if os.path.exists(backup_path):
                os.remove(backup_path)
            return None
    
    def restore_backup(self, backup_name, overwrite=False):
        """Restore from a backup"""
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.tar.gz")
        
        if not os.path.exists(backup_path):
            print(f"Error: Backup not found: {backup_path}")
            return False
        
        print(f"Restoring backup: {backup_name}")
        print(f"Source: {backup_path}")
        print(f"Destination: {self.upload_dir}")
        
        # Create upload directory if it doesn't exist
        if not os.path.exists(self.upload_dir):
            os.makedirs(self.upload_dir)
        
        try:
            with tarfile.open(backup_path, "r:gz") as tar:
                # Extract and read manifest
                manifest_member = tar.getmember('manifest.json')
                manifest_file = tar.extractfile(manifest_member)
                manifest = json.load(manifest_file)
                
                print(f"\nBackup info:")
                print(f"  Created: {manifest['created']}")
                print(f"  Files: {manifest['file_count']}")
                print(f"  Total Size: {self._format_size(manifest['total_size'])}")
                
                # Confirm restore
                if not overwrite:
                    confirm = input("\nProceed with restore? (yes/no): ")
                    if confirm.lower() != 'yes':
                        print("Restore cancelled")
                        return False
                
                # Extract files
                print("\nRestoring files:")
                restored_count = 0
                skipped_count = 0
                
                for member in tar.getmembers():
                    if member.name == 'manifest.json':
                        continue
                    
                    dest_path = os.path.join(self.upload_dir, member.name)
                    
                    # Check if file exists
                    if os.path.exists(dest_path) and not overwrite:
                        print(f"  ⊗ Skipped (exists): {member.name}")
                        skipped_count += 1
                        continue
                    
                    tar.extract(member, path=self.upload_dir)
                    print(f"  ✓ Restored: {member.name}")
                    restored_count += 1
                
                print(f"\n✓ Restore completed successfully")
                print(f"  Restored: {restored_count} files")
                if skipped_count > 0:
                    print(f"  Skipped: {skipped_count} files (already exist)")
                return True
                
        except Exception as e:
            print(f"Error restoring backup: {e}")
            return False
    
    def list_backups(self):
        """List all available backups"""
        if not os.path.exists(self.backup_dir):
            print("No backups found")
            return []
        
        backups = []
        for filename in os.listdir(self.backup_dir):
            if filename.endswith('.tar.gz'):
                filepath = os.path.join(self.backup_dir, filename)
                backup_info = {
                    'name': filename[:-7],  # Remove .tar.gz
                    'size': os.path.getsize(filepath),
                    'created': datetime.fromtimestamp(os.path.getctime(filepath)),
                }
                backups.append(backup_info)
        
        return backups
    
    def print_backups(self):
        """Print formatted backup list"""
        backups = self.list_backups()
        
        if not backups:
            print("No backups found")
            return
        
        print(f"\nAvailable backups in {self.backup_dir}:")
        print(f"{'Name':<50} {'Size':<15} {'Created':<20}")
        print("-" * 85)
        
        for backup in sorted(backups, key=lambda x: x['created'], reverse=True):
            size_str = self._format_size(backup['size'])
            created_str = backup['created'].strftime('%Y-%m-%d %H:%M:%S')
            print(f"{backup['name']:<50} {size_str:<15} {created_str:<20}")
        
        print(f"\nTotal: {len(backups)} backups")
    
    def delete_backup(self, backup_name):
        """Delete a backup"""
        backup_path = os.path.join(self.backup_dir, f"{backup_name}.tar.gz")
        
        if not os.path.exists(backup_path):
            print(f"Error: Backup not found: {backup_name}")
            return False
        
        try:
            os.remove(backup_path)
            print(f"✓ Deleted backup: {backup_name}")
            return True
        except Exception as e:
            print(f"Error deleting backup: {e}")
            return False
    
    def _create_manifest(self):
        """Create manifest of files being backed up"""
        manifest = {
            'created': datetime.now().isoformat(),
            'upload_dir': self.upload_dir,
            'files': [],
            'file_count': 0,
            'total_size': 0,
        }
        
        for filename in os.listdir(self.upload_dir):
            filepath = os.path.join(self.upload_dir, filename)
            if os.path.isfile(filepath):
                file_info = {
                    'filename': filename,
                    'size': os.path.getsize(filepath),
                    'hash': FileHandler.calculate_file_hash(filepath),
                    'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat(),
                }
                manifest['files'].append(file_info)
                manifest['total_size'] += file_info['size']
        
        manifest['file_count'] = len(manifest['files'])
        return manifest
    
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
        description='SecureFileX Backup and Restore Utility',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --backup                  # Create backup with auto name
  %(prog)s --backup my_backup        # Create backup with custom name
  %(prog)s --restore my_backup       # Restore from backup
  %(prog)s --list                    # List all backups
  %(prog)s --delete my_backup        # Delete a backup
        """
    )
    
    parser.add_argument('--upload-dir', help='Upload directory path')
    parser.add_argument('--backup-dir', default='backups', help='Backup directory path')
    parser.add_argument('--backup', nargs='?', const='', metavar='NAME', 
                       help='Create a backup')
    parser.add_argument('--restore', metavar='NAME', help='Restore from backup')
    parser.add_argument('--list', action='store_true', help='List all backups')
    parser.add_argument('--delete', metavar='NAME', help='Delete a backup')
    parser.add_argument('--overwrite', action='store_true', 
                       help='Overwrite existing files during restore')
    
    args = parser.parse_args()
    
    # Create backup manager
    bm = BackupManager(upload_dir=args.upload_dir, backup_dir=args.backup_dir)
    
    # Execute commands
    if args.backup is not None:
        bm.create_backup(backup_name=args.backup if args.backup else None)
    elif args.restore:
        bm.restore_backup(args.restore, overwrite=args.overwrite)
    elif args.list:
        bm.print_backups()
    elif args.delete:
        bm.delete_backup(args.delete)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
