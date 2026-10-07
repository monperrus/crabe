"""Tests for the standalone crabe agent."""

from __future__ import annotations

import importlib.util
import logging
import subprocess
from pathlib import Path

import pytest


def load_crabe():
    spec = importlib.util.spec_from_file_location(
        "crabe_under_test", Path(__file__).parents[1] / "crabe.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_setup_logging_creates_daily_30_day_rotating_log(tmp_path, monkeypatch):
    crabe = load_crabe()
    log_file = tmp_path / "logs" / "crabe.log"
    monkeypatch.setattr(crabe, "LOG_FILE", str(log_file))
    monkeypatch.setattr(crabe, "logger", logging.getLogger("crabe-test"))

    crabe.setup_logging()
    crabe.log("logged event")

    handlers = crabe.logger.handlers
    assert len(handlers) == 1
    assert handlers[0].when == "MIDNIGHT"
    assert handlers[0].backupCount == 30
    assert "logged event" in log_file.read_text()


def ssh_keygen_check(signature: str, message: bytes, tmp_path: Path) -> bool:
    sig_file = tmp_path / "msg.sig"
    sig_file.write_text(signature + "\n")
    result = subprocess.run(
        ["ssh-keygen", "-Y", "check-novalidate", "-n", "file", "-s", str(sig_file)],
        input=message,
        capture_output=True,
    )
    return result.returncode == 0


def test_ssh_signature_verifies_with_ssh_keygen(tmp_path):
    pytest.importorskip("paramiko")
    crabe = load_crabe()
    key_path = tmp_path / "id_ed25519"
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key_path)], check=True
    )
    key = crabe.paramiko.Ed25519Key.from_private_key_file(str(key_path))
    signature = crabe.create_ssh_signature(key, "file", b"machine-id")

    assert ssh_keygen_check(signature, b"machine-id", tmp_path)
    assert not ssh_keygen_check(signature, b"other-id", tmp_path)


def test_ensure_ssh_key_creates_passphraseless_dedicated_key(tmp_path, monkeypatch):
    crabe = load_crabe()
    key_path = tmp_path / "crabe" / "id_ed25519"
    monkeypatch.setattr(crabe, "SSH_KEY_PATH", str(key_path))

    crabe.ensure_ssh_key_exists()

    public = subprocess.run(
        ["ssh-keygen", "-y", "-P", "", "-f", str(key_path)],
        capture_output=True, text=True, check=True,
    ).stdout
    assert public.startswith("ssh-ed25519 ")


def test_log_is_silent_on_success_and_loud_on_error(capsys, monkeypatch):
    crabe = load_crabe()
    monkeypatch.setattr(crabe, "logger", logging.getLogger("crabe-silence-test"))

    crabe.log("Data sent. Status code: 200")
    assert capsys.readouterr().out == ""

    crabe.log("Update failed: boom", logging.ERROR)
    assert capsys.readouterr().out == "Update failed: boom\n"


def test_parse_version():
    crabe = load_crabe()
    source = (Path(__file__).parents[1] / "crabe.py").read_bytes()

    assert crabe.parse_version(source) == crabe.CRABE_VERSION
    assert crabe.parse_version(b"#!/usr/bin/python3\nprint('old crabe')\n") == 0
    assert crabe.parse_version(b"x = 1\nCRABE_VERSION = 12\n") == 12


def test_stagger_fits_under_cron_timeout():
    crabe = load_crabe()
    assert crabe.STAGGER_MAX_SECONDS <= 50
