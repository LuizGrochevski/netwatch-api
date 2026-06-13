import subprocess
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

SENTINEL_BIN = os.path.expanduser("~/sentinel-rs/target/release/sentinel-rs")
DEFAULT_PORTS = "21,22,23,25,53,80,443,3306,5432,6379,8080"

def run_sentinel(targets: list, ports: str = DEFAULT_PORTS, protocol: str = "tcp") -> list:
    if len(targets) == 1:
        return [_scan_target(targets[0], ports, protocol)]

    results = [None] * len(targets)
    with ThreadPoolExecutor(max_workers=min(len(targets), 5)) as executor:
        futures = {executor.submit(_scan_target, t, ports, protocol): i for i, t in enumerate(targets)}
        for future in as_completed(futures):
            idx = futures[future]
            results[idx] = future.result()
    return results

def _scan_target(target: str, ports: str, protocol: str = "tcp") -> dict:
    try:
        cmd = [SENTINEL_BIN, target, "-p", ports, "--stdout"]
        if protocol.lower() == "udp":
            cmd.append("-udp")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        if proc.stdout.strip():
            raw = json.loads(proc.stdout.strip())
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
