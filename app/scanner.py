import subprocess
import tempfile
import json
import os

SENTINEL_BIN = os.path.expanduser("~/sentinel-rs/target/release/sentinel-rs")
DEFAULT_PORTS = "21,22,23,25,53,80,443,3306,5432,6379,8080"

def run_sentinel(targets: list, ports: str = DEFAULT_PORTS) -> list:
    results = []
    for target in targets:
        result = _scan_target(target, ports)
        results.append(result)
    return results

def _scan_target(target: str, ports: str) -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            proc = subprocess.run(
                [SENTINEL_BIN, target, "-p", ports],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=tmpdir
            )
            report_path = os.path.join(tmpdir, "reports", "relatorio.json")
            if os.path.exists(report_path):
                with open(report_path) as f:
                    raw = json.load(f)
                open_ports = [
                    {"port": r["porta"], "service": r["servico"], "status": r["status"]}
                    for r in raw
                ]
                return {
                    "target": target,
                    "engine": "sentinel-rs",
                    "open_ports": open_ports,
                    "error": None
                }
            else:
                return {
                    "target": target,
                    "engine": "sentinel-rs",
                    "open_ports": [],
                    "error": "Host unreachable or no ports found"
                }
        except subprocess.TimeoutExpired:
            return {"target": target, "engine": "sentinel-rs", "open_ports": [], "error": "Timeout"}
        except Exception as e:
            return {"target": target, "engine": "sentinel-rs", "open_ports": [], "error": str(e)}
