"""Google Cloud side: deploy a Cloud Run Job running stock nmap, execute it
against an IP, and read the nmap output back from Cloud Logging.

Only REST calls via google-auth; no gcloud SDK needed in the container.
"""
import time
from datetime import datetime, timedelta, timezone

from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import service_account

RUN = "https://run.googleapis.com/v2"
LOGGING = "https://logging.googleapis.com/v2"
SERVICEUSAGE = "https://serviceusage.googleapis.com/v1"
REQUIRED_APIS = ["run.googleapis.com", "logging.googleapis.com"]


class GCPError(RuntimeError):
    pass


def _check(resp, what):
    if resp.status_code >= 400:
        try:
            msg = resp.json().get("error", {}).get("message", resp.text)
        except ValueError:
            msg = resp.text
        raise GCPError(f"{what} failed ({resp.status_code}): {msg}")
    return resp.json() if resp.content else {}


class CloudRunScanner:
    def __init__(self, key_path, region, job_name):
        self.creds = service_account.Credentials.from_service_account_file(
            key_path, scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        self.project = self.creds.project_id
        self.sa_email = self.creds.service_account_email
        self.region = region
        self.job_name = job_name
        self.s = AuthorizedSession(self.creds)
        self.s.timeout = 30

    @property
    def parent(self):
        return f"projects/{self.project}/locations/{self.region}"

    @property
    def job_path(self):
        return f"{self.parent}/jobs/{self.job_name}"

    # ---------- setup ----------
    def enable_apis(self):
        """Best effort: needs roles/serviceusage.serviceUsageAdmin. Returns message."""
        r = self.s.post(
            f"{SERVICEUSAGE}/projects/{self.project}/services:batchEnable",
            json={"serviceIds": REQUIRED_APIS},
        )
        if r.status_code == 403:
            return "Could not enable APIs (no permission) - assuming they are already enabled."
        op = _check(r, "Enable APIs")
        self._wait_op(op, base=SERVICEUSAGE, timeout=180)
        return "Cloud Run + Logging APIs enabled."

    def _job_body(self, image):
        return {
            "labels": {"app": "sixy"},
            "template": {
                "taskCount": 1,
                "parallelism": 1,
                "template": {
                    "containers": [{
                        "image": image,
                        "resources": {"limits": {"cpu": "1", "memory": "512Mi"}},
                    }],
                    "timeout": "3600s",
                    "maxRetries": 0,
                    "serviceAccount": self.sa_email,
                },
            },
        }

    def ensure_job(self, image):
        r = self.s.get(f"{RUN}/{self.job_path}")
        if r.status_code == 404:
            op = _check(
                self.s.post(f"{RUN}/{self.parent}/jobs", params={"jobId": self.job_name}, json=self._job_body(image)),
                "Create Cloud Run job",
            )
            self._wait_op(op)
            return f"Created job {self.job_name} in {self.region}."
        _check(r, "Read Cloud Run job")
        op = _check(self.s.patch(f"{RUN}/{self.job_path}", json=self._job_body(image)), "Update Cloud Run job")
        self._wait_op(op)
        return f"Updated job {self.job_name} in {self.region}."

    def _wait_op(self, op, base=RUN, timeout=300):
        deadline = time.time() + timeout
        while not op.get("done"):
            if time.time() > deadline:
                raise GCPError(f"Timed out waiting for operation {op.get('name')}")
            time.sleep(3)
            op = _check(self.s.get(f"{base}/{op['name']}"), "Poll operation")
        if "error" in op:
            raise GCPError(f"Operation failed: {op['error'].get('message')}")
        return op

    # ---------- scanning ----------
    def run_scan(self, nmap_args, timeout_s=3600):
        """Execute the job with nmap args; return (execution_name, stdout_lines)."""
        started = datetime.now(timezone.utc) - timedelta(seconds=30)
        op = _check(
            self.s.post(
                f"{RUN}/{self.job_path}:run",
                json={"overrides": {"containerOverrides": [{"args": nmap_args}], "timeout": f"{timeout_s}s"}},
            ),
            "Run Cloud Run job",
        )
        exec_name = (op.get("metadata") or {}).get("name")
        if not exec_name:
            op = self._wait_op(op, timeout=timeout_s + 120)
            exec_name = op["response"]["name"]

        ex = self._wait_execution(exec_name, timeout_s + 120)
        lines = self._read_stdout(exec_name.rsplit("/", 1)[-1], started)
        if not ex.get("succeededCount") and not any(l.startswith("# Nmap done") for l in lines):
            raise GCPError(f"Scan execution failed. Logs: {ex.get('logUri', 'n/a')}\n" + "\n".join(lines[-20:]))
        return exec_name.rsplit("/", 1)[-1], lines

    def _wait_execution(self, exec_name, timeout):
        deadline = time.time() + timeout
        while True:
            ex = _check(self.s.get(f"{RUN}/{exec_name}"), "Poll execution")
            if ex.get("completionTime"):
                return ex
            if time.time() > deadline:
                raise GCPError("Timed out waiting for scan execution")
            time.sleep(5)

    def _read_stdout(self, exec_short, since, wait=120):
        """Log ingestion lags a few seconds; poll until nmap's final line shows."""
        flt = (
            'resource.type="cloud_run_job" '
            f'AND resource.labels.job_name="{self.job_name}" '
            f'AND labels."run.googleapis.com/execution_name"="{exec_short}" '
            f'AND logName="projects/{self.project}/logs/run.googleapis.com%2Fstdout" '
            f'AND timestamp>="{since.strftime("%Y-%m-%dT%H:%M:%SZ")}"'
        )
        deadline = time.time() + wait
        lines = []
        while True:
            lines, token = [], None
            while True:
                body = {"resourceNames": [f"projects/{self.project}"], "filter": flt,
                        "orderBy": "timestamp asc", "pageSize": 1000}
                if token:
                    body["pageToken"] = token
                data = _check(self.s.post(f"{LOGGING}/entries:list", json=body), "Read scan logs")
                for e in data.get("entries", []):
                    lines.append((e.get("textPayload") or "").rstrip("\n"))
                token = data.get("nextPageToken")
                if not token:
                    break
            if any(l.startswith("# Nmap done") for l in lines) or time.time() > deadline:
                return lines
            time.sleep(5)
