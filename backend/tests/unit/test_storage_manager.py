from backend.app.backup.storage_manager import BackupStorageManager


def test_create_recovery_point(tmp_path):
    storage = BackupStorageManager(str(tmp_path / "storage"))

    recovery_point = storage.create_recovery_point("backup-001")

    assert recovery_point.exists()
    assert recovery_point.is_dir()
    assert recovery_point.name == "backup-001"


def test_cannot_overwrite_existing_recovery_point(tmp_path):
    storage = BackupStorageManager(str(tmp_path / "storage"))

    storage.create_recovery_point("backup-001")

    try:
        storage.create_recovery_point("backup-001")
        assert False
    except FileExistsError:
        assert True


def test_recovery_point_exists(tmp_path):
    storage = BackupStorageManager(str(tmp_path / "storage"))

    assert storage.recovery_point_exists("backup-001") is False

    storage.create_recovery_point("backup-001")

    assert storage.recovery_point_exists("backup-001") is True


def test_get_recovery_point(tmp_path):
    storage = BackupStorageManager(str(tmp_path / "storage"))

    recovery_point = storage.create_recovery_point("backup-001")

    assert storage.get_recovery_point("backup-001") == recovery_point


def test_list_recovery_points(tmp_path):
    storage = BackupStorageManager(str(tmp_path / "storage"))

    storage.create_recovery_point("backup-002")
    storage.create_recovery_point("backup-001")
    storage.create_recovery_point("backup-003")

    recovery_points = storage.list_recovery_points()

    assert [point.name for point in recovery_points] == [
        "backup-001",
        "backup-002",
        "backup-003",
    ]