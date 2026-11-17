"""Exercise the Cloud Run / Logging REST flow against a fake HTTP session."""
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import gcp


@pytest.fixture
def key_file(tmp_path):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    p = tmp_path / "key.json"
    p.write_text(json.dumps({
        "type": "service_account", "project_id": "proj-x", "private_key_id": "1", "private_key": pem,
        "client_email": "wanwatch@proj-x.iam.gserviceaccount.com", "client_id": "1",
        "token_uri": "https://oauth2.googleapis.com/token",
    }))
    return str(p)


class Resp:
    def __init__(self, code, data):
        self.status_code, self._d = code, data
        self.content = b"x"
        self.text = json.dumps(data)

    def json(self):
        return self._d


class FakeGoogle:
    def __init__(self, job_exists=False, exec_fails=False):
        self.calls, self.job_exists, self.exec_fails = [], job_exists, exec_fails
        self.exec_polls = self.log_polls = 0

    def __call__(self, method, url, **kw):
        self.calls.append((method, url, kw.get("json"), kw.get("params")))
        if "batchEnable" in url:
            return Resp(403, {"error": {"message": "denied"}})
        if method == "GET" and url.endswith("/jobs/wanwatch-scan"):
            return Resp(200, {}) if self.job_exists else Resp(404, {})
        if method in ("POST", "PATCH") and (url.endswith("/jobs") or url.endswith("/jobs/wanwatch-scan")):
            return Resp(200, {"name": "projects/proj-x/locations/us-west1/operations/op1", "done": False})
        if "operations/op1" in url:
            return Resp(200, {"name": "op1", "done": True})
        if url.endswith(":run"):
            return Resp(200, {"name": "projects/proj-x/locations/us-west1/operations/op2", "metadata": {
                "name": "projects/proj-x/locations/us-west1/jobs/wanwatch-scan/executions/wanwatch-scan-abc12"}})
        if "/executions/" in url:
            self.exec_polls += 1
            if self.exec_polls < 2:
                return Resp(200, {})
            return Resp(200, {"completionTime": "t", "failedCount": 1} if self.exec_fails
                        else {"completionTime": "t", "succeededCount": 1})
        if "entries:list" in url:
            self.log_polls += 1
            if self.log_polls == 1 or self.exec_fails:
                return Resp(200, {})
            return Resp(200, {"entries": [
                {"textPayload": "Host: 1.2.3.4 ()\tPorts: 443/open/tcp//https///\n"},
                {"textPayload": "# Nmap done at x"}]})
        return Resp(500, {"error": {"message": "unexpected " + url}})


@pytest.fixture
def scanner_with(key_file, monkeypatch):
    monkeypatch.setattr(gcp.time, "sleep", lambda s: None)

    def make(fake):
        sc = gcp.CloudRunScanner(key_file, "us-west1", "wanwatch-scan")
        sc.s.request = lambda method, url, **kw: fake(method, url, **kw)
        return sc
    return make


def test_deploy_creates_job_when_missing(scanner_with):
    fake = FakeGoogle()
    sc = scanner_with(fake)
    assert "no permission" in sc.enable_apis()
    assert sc.ensure_job("docker.io/instrumentisto/nmap:latest").startswith("Created")
    create = next(c for c in fake.calls if c[0] == "POST" and c[1].endswith("/jobs"))
    assert create[3] == {"jobId": "wanwatch-scan"}
    tmpl = create[2]["template"]["template"]
    assert tmpl["serviceAccount"] == "wanwatch@proj-x.iam.gserviceaccount.com"
    assert tmpl["containers"][0]["image"] == "docker.io/instrumentisto/nmap:latest"


def test_deploy_updates_existing_job(scanner_with):
    fake = FakeGoogle(job_exists=True)
    assert scanner_with(fake).ensure_job("img").startswith("Updated")
    assert any(c[0] == "PATCH" for c in fake.calls)


def test_run_scan_passes_args_and_reads_logs(scanner_with):
    fake = FakeGoogle()
    exec_name, lines = scanner_with(fake).run_scan(["-Pn", "1.2.3.4"], 900)
    assert exec_name == "wanwatch-scan-abc12"
    assert lines[-1].startswith("# Nmap done")
    run = next(c for c in fake.calls if c[1].endswith(":run"))
    assert run[2]["overrides"]["containerOverrides"][0]["args"] == ["-Pn", "1.2.3.4"]
    log_req = next(c for c in fake.calls if "entries:list" in c[1])
    assert 'execution_name"="wanwatch-scan-abc12"' in log_req[2]["filter"]


def test_failed_execution_raises(scanner_with, monkeypatch):
    monkeypatch.setattr(gcp.time, "time", iter(range(0, 10**6, 100)).__next__)
    with pytest.raises(gcp.GCPError, match="failed"):
        scanner_with(FakeGoogle(exec_fails=True)).run_scan(["x"], 900)
