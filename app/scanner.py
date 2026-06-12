import subprocess
import tempfile
import json
import os

SENTINEL_BIN = os.path.expanduser("~/sentinel-rs/target/release/sentinel-rs")
DEFAULT_PORTS = "21,22,23,25,53,80,443,3306,5432,6379,8080"

def run_sentinel(targets: list, ports: str = DEFAULT_PORTS, protocol: str = "tcp") -> list:
    results = []
    for target in targets:
        result = _scan_target(target, ports, protocol)
        results.append(result)
    return results

def _scan_target(target: str, ports: str, protocol: str = "tcp") -> dict:
    with tempfile.TemporaryDirectory() as tmpdir:
        try:
            cmd = [SENTINEL_BIN, target, "-p", ports]
            if protocol.lower() == "udp":
                cmd.append("-udp")

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
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
                    "protocol": protocol,
                    "ports_scanned": ports,
                    "open_ports": open_ports,
                    "error": None
                }
            else:
                return {
                    "target": target,
                    "engine": "sentinel-rs",
                    "protocol": protocol,
                    "ports_scanned": ports,
                    "open_ports": [],
                    "error": "Host unreachable or no ports found"
                }
        except subprocess.TimeoutExpired:
            return {"target": target, "engine": "sentinel-rs", "protocol": protocol, "ports_scanned": ports, "open_ports": [], "error": "Timeout"}
        except Exception as e:
            return {"target": target, "engine": "sentinel-rs", "protocol": protocol, "ports_scanned": ports, "open_ports": [], "error": str(e)}
