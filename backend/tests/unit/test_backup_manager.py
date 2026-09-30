from backend.app.backup.backup_manager import BackupManager


def test_backup_fails_when_source_does_not_exist(tmp_path):
    manager = BackupManager()

    result = manager.create_backup(
        "backup-001",
        str(tmp_path / "missing"),
        str(tmp_path / "backup"),
    )

    assert result.status == "FAILED"
    assert result.error == "Source path does not exist."


def test_backup_fails_when_source_is_not_directory(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("test data")

    manager = BackupManager()

    result = manager.create_backup(
        "backup-002",
        str(source),
        str(tmp_path / "backup"),
    )

    assert result.status == "FAILED"
    assert result.error == "Source path is not a directory."


def test_backup_result_to_dict(tmp_path):
    manager = BackupManager()

    result = manager.create_backup(
        "backup-003",
        str(tmp_path / "missing"),
        str(tmp_path / "backup"),
    )

    data = result.to_dict()

    assert data["backup_id"] == "backup-003"
    assert data["status"] == "FAILED"
    assert data["source_path"] == str(tmp_path / "missing")
    assert data["destination_path"] == str(tmp_path / "backup")


def test_backup_succeeds(tmp_path, monkeypatch):
    source = tmp_path / "source"
    destination = tmp_path / "backup"

    source.mkdir()
    (source / "file.txt").write_text("backup data")

    def fake_rsync(*args, **kwargs):
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "file.txt").write_text("backup data")

    monkeypatch.setattr(
        "backend.app.backup.backup_manager.subprocess.run",
        fake_rsync,
    )

    manager = BackupManager()

    result = manager.create_backup(
        "backup-004",
        str(source),
        str(destination),
    )

    assert result.status == "COMPLETED"
    assert result.file_count == 1
    assert result.size_bytes == len("backup data")
    assert result.error is None
    assert (destination / "file.txt").read_text() == "backup data"


def test_backup_passes_rsync_arguments(tmp_path, monkeypatch):
    source = tmp_path / "source"
    destination = tmp_path / "backup"

    source.mkdir()

    captured = {}

    def fake_rsync(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs

    monkeypatch.setattr(
        "backend.app.backup.backup_manager.subprocess.run",
        fake_rsync,
    )

    manager = BackupManager()

    result = manager.create_backup(
        "backup-005",
        str(source),
        str(destination),
    )

    assert result.status == "COMPLETED"
    assert captured["command"][0] == "rsync"
    assert captured["command"][1] == "-a"
    assert captured["command"][2] == "--delete"
    assert captured["kwargs"]["check"] is True
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True