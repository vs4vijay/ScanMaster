import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


class ZapFixture(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.startswith("/JSON/automation/action/runPlan/"):
            self._send({"planId": "fixture-plan-1"})
        elif self.path.startswith("/JSON/automation/view/planProgress/"):
            self._send({"state": "completed", "planId": "fixture-plan-1"})
        elif self.path.startswith("/JSON/core/view/alerts/"):
            self._send(
                {
                    "alerts": [
                        {
                            "pluginId": "10021",
                            "name": "Missing header",
                            "risk": "Low",
                            "url": "http://127.0.0.1/",
                            "description": "Fixture finding",
                        }
                    ]
                }
            )
        else:
            self._send({"Result": "OK"})


def run_cli(tmp_path: Path, *arguments: str, zap_url: str) -> subprocess.CompletedProcess[str]:
    env = {key: value for key, value in os.environ.items() if not key.startswith("SCANMASTER_")}
    env.update(
        {
            "SCANMASTER_ZAP_ENABLED": "true",
            "SCANMASTER_ZAP_URL": zap_url,
            "SCANMASTER_DATABASE_PATH": str(tmp_path / "state.db"),
            "SCANMASTER_ARTIFACT_PATH": str(tmp_path / "artifacts"),
            "SCANMASTER_ZAP_PLAN_HOST_DIRECTORY": str(tmp_path / "zap-plans"),
            "SCANMASTER_POLLING_INTERVAL_SECONDS": "0.01",
        }
    )
    return subprocess.run(
        [sys.executable, "-m", "scanmaster", *arguments],
        cwd=tmp_path,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def test_passive_zap_scan_persists_across_processes(tmp_path: Path) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), ZapFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    zap_url = f"http://127.0.0.1:{server.server_port}"
    try:
        scan = run_cli(tmp_path, "scan", "http://127.0.0.1:43199", "--scanner", "zap", zap_url=zap_url)
        assert scan.returncode == 0, scan.stderr
        match = re.search(r"Run ([0-9a-f-]{36})", scan.stdout)
        assert match
        run_id = match.group(1)
        status = run_cli(tmp_path, "status", run_id, zap_url=zap_url)
        report = run_cli(tmp_path, "report", run_id, "--format", "json", zap_url=zap_url)
        assert status.returncode == 0 and "completed" in status.stdout
        assert report.returncode == 0
        payload = json.loads(report.stdout)
        assert payload["findings"][0]["native_id"] == "10021"
        assert (tmp_path / "artifacts" / run_id / "submission.json").is_file()
    finally:
        server.shutdown()
        thread.join()
