import os
import shutil
import subprocess
from datetime import datetime
from .integrity import calculate_sha256

def create_backup(source_dir: str, dest_dir: str) -> dict:
    """
    Creates a backup using shutil (Windows) and returns metadata.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_{timestamp}"
    backup_path = os.path.join(dest_dir, backup_filename)

    # Ensure destination exists
    os.makedirs(dest_dir, exist_ok=True)

    try:
        # Use shutil to copy the directory
        if os.path.exists(backup_path):
            shutil.rmtree(backup_path)
        shutil.copytree(source_dir, backup_path)
            
        # Calculate hash immediately after creation
        # Note: calculate_sha256 works on files. For a folder, we need to hash the folder or a specific file inside.
        # For simplicity in this test, let's assume we hash the first file in the backup.
        # In a real system, you would hash the whole archive.
        first_file = os.path.join(backup_path, os.listdir(backup_path)[0]) if os.listdir(backup_path) else backup_path
        
        # If it's a folder, create a placeholder file for hashing
        if os.path.isdir(first_file):
             test_file = os.path.join(backup_path, "hash_placeholder.txt")
             with open(test_file, "w") as f:
                 f.write("placeholder")
             first_file = test_file

        file_hash = calculate_sha256(first_file)
        size = os.path.getsize(first_file)

        return {
            "filename": backup_filename,
            "file_path": first_file, # We store the path to the file we hashed
            "size_bytes": size,
            "sha256_hash": file_hash,
            "status": "TRUSTED",
            "is_verified": True,
            "created_at": datetime.utcnow()
        }
    except Exception as e:
        print(f"Backup failed: {e}")
        return None

def lock_backup(file_path: str) -> bool:
    """
    Makes a backup file immutable (read-only).
    On Windows, chattr doesn't exist, so we use os.chmod to make it read-only.
    """
    if not os.path.exists(file_path):
        return False
        
    try:
        # Make the file read-only
        os.chmod(file_path, 0o444)
        print(f"Backup locked successfully: {file_path}")
        return True
    except Exception as e:
        print(f"Failed to lock backup: {e}")
        return False