from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any

from .manager import create_backup, lock_backup
from .verification import is_backup_safe_for_recovery

router = APIRouter(prefix="/api/backup", tags=["Backup"])

# Temporary in-memory storage for testing (Member 6 will replace this with a real DB)
backup_registry: Dict[int, Dict[str, Any]] = {}
next_id = 1

class BackupCreateRequest(BaseModel):
    source_dir: str
    dest_dir: str

@router.post("/create")
def trigger_backup(request: BackupCreateRequest):
    """API endpoint for Member 6's Dashboard to trigger a new backup."""
    global next_id
    result = create_backup(request.source_dir, request.dest_dir)
    
    if not result:
        raise HTTPException(status_code=500, detail="Backup creation failed")
    
    # Store metadata in our temporary registry
    backup_registry[next_id] = result
    result["id"] = next_id
    next_id += 1
    
    return {"message": "Backup created successfully", "data": result}

@router.post("/backups/{backup_id}/verify")
def verify_backup_endpoint(backup_id: int):
    """
    API endpoint for Member 6's Dashboard.
    Verifies if a backup is safe and updates its status.
    """
    if backup_id not in backup_registry:
        raise HTTPException(status_code=404, detail="Backup record not found")

    backup_record = backup_registry[backup_id]

    # Call YOUR verification function
    is_safe = is_backup_safe_for_recovery(
        backup_record["file_path"], 
        backup_record["sha256_hash"]
    )

    # Update status
    backup_record["status"] = "TRUSTED" if is_safe else "UNTRUSTED"
    backup_record["is_verified"] = is_safe

    return {
        "backup_id": backup_id,
        "is_safe": is_safe,
        "status": backup_record["status"],
        "message": "Backup is safe for recovery." if is_safe else "WARNING: Backup integrity compromised!"
    }

@router.get("/backups")
def list_backups():
    """API endpoint to list all backups for the dashboard."""
    return {"backups": list(backup_registry.values())}