"""
Unit tests for backend.app.backup.encryption.
"""

import pytest
from cryptography.fernet import Fernet, InvalidToken

from backend.app.backup.encryption import (
    ENCRYPTED_SUFFIX,
    decrypt_backup_dir,
    decrypt_file,
    encrypt_backup_dir,
    encrypt_file,
    generate_key,
    is_encrypted,
    load_key,
    save_key,
)


# -----------------------------------------------------------------------------
# Key management
# -----------------------------------------------------------------------------

def test_generate_key_returns_valid_fernet_key():
    key = generate_key()
    # Should not raise
    Fernet(key)


def test_save_and_load_key_round_trip(tmp_path):
    key = generate_key()
    key_path = tmp_path / "sub" / "backup.key"

    save_key(key, key_path)
    loaded = load_key(key_path)

    assert loaded == key


# -----------------------------------------------------------------------------
# encrypt_file / decrypt_file
# -----------------------------------------------------------------------------

def test_encrypt_then_decrypt_returns_original(tmp_path):
    key = generate_key()
    source = tmp_path / "plain.txt"
    source.write_text("secret data")

    encrypted = tmp_path / "plain.txt.enc"
    decrypted = tmp_path / "plain_recovered.txt"

    encrypt_file(source, encrypted, key)
    decrypt_file(encrypted, decrypted, key)

    assert decrypted.read_text() == "secret data"


def test_encrypted_file_differs_from_plaintext(tmp_path):
    key = generate_key()
    source = tmp_path / "plain.txt"
    source.write_text("secret data")

    encrypted = tmp_path / "plain.txt.enc"
    encrypt_file(source, encrypted, key)

    assert encrypted.read_bytes() != source.read_bytes()


def test_decrypt_with_wrong_key_raises_invalid_token(tmp_path):
    key1 = generate_key()
    key2 = generate_key()
    source = tmp_path / "plain.txt"
    source.write_text("secret data")

    encrypted = tmp_path / "plain.txt.enc"
    encrypt_file(source, encrypted, key1)

    with pytest.raises(InvalidToken):
        decrypt_file(encrypted, tmp_path / "out.txt", key2)


def test_encrypt_file_raises_for_missing_source(tmp_path):
    key = generate_key()

    with pytest.raises(FileNotFoundError):
        encrypt_file(tmp_path / "missing.txt", tmp_path / "out.enc", key)


# -----------------------------------------------------------------------------
# is_encrypted
# -----------------------------------------------------------------------------

def test_is_encrypted_recognises_suffix(tmp_path):
    assert is_encrypted("file.txt" + ENCRYPTED_SUFFIX) is True
    assert is_encrypted("file.txt") is False


# -----------------------------------------------------------------------------
# encrypt_backup_dir / decrypt_backup_dir
# -----------------------------------------------------------------------------

def _make_backup(tmp_path):
    backup = tmp_path / "backup-001"
    backup.mkdir()
    (backup / "file1.txt").write_text("data1")
    (backup / "sub").mkdir()
    (backup / "sub" / "file2.txt").write_text("data2")
    return backup


def test_encrypt_backup_dir_round_trip(tmp_path):
    key = generate_key()
    backup = _make_backup(tmp_path)
    encrypted_dir = tmp_path / "encrypted"
    decrypted_dir = tmp_path / "decrypted"

    enc_result = encrypt_backup_dir(backup, encrypted_dir, key)
    assert enc_result.success is True
    assert enc_result.file_count == 2
    assert (encrypted_dir / "file1.txt.enc").exists()
    assert (encrypted_dir / "sub" / "file2.txt.enc").exists()

    dec_result = decrypt_backup_dir(encrypted_dir, decrypted_dir, key)
    assert dec_result.success is True
    assert dec_result.file_count == 2
    assert (decrypted_dir / "file1.txt").read_text() == "data1"
    assert (decrypted_dir / "sub" / "file2.txt").read_text() == "data2"


def test_encrypt_backup_dir_fails_for_missing_source(tmp_path):
    key = generate_key()
    result = encrypt_backup_dir(tmp_path / "missing", tmp_path / "out", key)

    assert result.success is False
    assert len(result.errors) > 0
def test_decrypt_backup_dir_reports_invalid_token(tmp_path):
    key1 = generate_key()
    key2 = generate_key()
    backup = _make_backup(tmp_path)
    encrypted_dir = tmp_path / "encrypted"
    encrypt_backup_dir(backup, encrypted_dir, key1)

    # Decrypt with wrong key
    result = decrypt_backup_dir(encrypted_dir, tmp_path / "out", key2)

    assert result.success is False
    assert any("authentication" in e.lower() for e in result.errors)    