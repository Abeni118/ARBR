from backend.app.backup.recovery_point import RecoveryPoint


def test_recovery_point_creation():
    recovery_point = RecoveryPoint.create(
        backup_id="backup-001",
        source_path="/data/source",
        destination_path="/backup/backup-001",
        status="COMPLETED",
        file_count=10,
        size_bytes=2048,
    )

    assert recovery_point.backup_id == "backup-001"
    assert recovery_point.source_path == "/data/source"
    assert recovery_point.destination_path == "/backup/backup-001"
    assert recovery_point.status == "COMPLETED"
    assert recovery_point.file_count == 10
    assert recovery_point.size_bytes == 2048
    assert recovery_point.integrity_status == "UNVERIFIED"
    assert recovery_point.created_at


def test_recovery_point_to_dict():
    recovery_point = RecoveryPoint.create(
        backup_id="backup-002",
        source_path="/data/source",
        destination_path="/backup/backup-002",
        status="COMPLETED",
        file_count=5,
        size_bytes=1024,
    )

    data = recovery_point.to_dict()

    assert data["backup_id"] == "backup-002"
    assert data["status"] == "COMPLETED"
    assert data["file_count"] == 5
    assert data["size_bytes"] == 1024
    assert data["integrity_status"] == "UNVERIFIED"
    assert "created_at" in data


def test_recovery_point_integrity_status_can_change():
    recovery_point = RecoveryPoint.create(
        backup_id="backup-003",
        source_path="/data/source",
        destination_path="/backup/backup-003",
        status="COMPLETED",
        file_count=3,
        size_bytes=512,
    )

    recovery_point.integrity_status = "TRUSTED"

    assert recovery_point.integrity_status == "TRUSTED"