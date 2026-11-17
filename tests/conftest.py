import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DATA_DIR", "/tmp/wanwatch-test-default")

from app import scanner, store  # noqa: E402


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """Point all storage at a fresh temp dir and use the demo backend."""
    monkeypatch.setattr(store, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(store, "CONFIG_PATH", str(tmp_path / "config.json"))
    monkeypatch.setattr(store, "KEY_PATH", str(tmp_path / "gcp-key.json"))
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "wanwatch.db"))
    monkeypatch.setattr(scanner, "BACKEND", "demo")
    monkeypatch.setattr(scanner.time, "sleep", lambda s: None)
    monkeypatch.setattr(scanner, "internetdb", lambda ip: {"ports": [443], "vulns": [], "cpes": [], "hostnames": [], "tags": []})
    scanner.state.update(running=False, next_run=None, last_error="")
    store.init_db()
    return tmp_path


@pytest.fixture
def configured(data_dir):
    cfg = store.load_config()
    cfg.update(allowed_ports=[443, 32400], target_override="198.51.100.7", job_deployed=True)
    store.save_config(cfg)
    return cfg
