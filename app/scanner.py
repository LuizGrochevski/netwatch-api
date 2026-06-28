import subprocess
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import os

SENTINEL_BIN = os.environ.get("SENTINEL_BIN_PATH", "/usr/local/bin/sentinel-rs")
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
    # 1. Tenta rodar com performance máxima usando SYN Scan
    result = _execute_sentinel_command(target, ports, protocol, use_syn=True)
    
    # 2. Fallback: Se o SYN scan não achou nenhuma porta aberta (qualquer motivo: erro,
    #    permissão, ping/host discovery falho), tenta o Connect Scan clássico via TCP.
    if protocol.lower() == "tcp" and not result.get("open_ports"):
        result_fallback = _execute_sentinel_command(target, ports, protocol, use_syn=False)
        if result_fallback.get("error") is None or len(result_fallback.get("open_ports", [])) > 0:
            return result_fallback

    return result

def _execute_sentinel_command(target: str, ports: str, protocol: str, use_syn: bool) -> dict:
    try:
        cmd = [SENTINEL_BIN, target, "-p", ports, "--stdout"]
        
        if protocol.lower() == "udp":
            cmd.append("--udp")
        elif use_syn:
            cmd.append("--syn")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        # Se houver erro explícito no stderr, captura para sabermos o que houve
        if proc.stderr and not proc.stdout.strip():
            return {
                "target": target,
                "engine": "sentinel-rs",
                "protocol": protocol,
                "ports_scanned": ports,
                "open_ports": [],
                "error": f"Engine Error: {proc.stderr.strip()}"
            }

        if proc.stdout.strip():
            raw = json.loads(proc.stdout.strip())
            open_ports = []
            for r in raw:
                port = r.get("port") or r.get("porta")
                service = r.get("service") or r.get("servico") or "Unknown"
                status = r.get("status") or "Aberta"
                
                if port is not None:
                    open_ports.append({
                        "port": int(port),
                        "service": service,
                        "status": status
                    })

            if not open_ports:
                return {
                    "target": target,
                    "engine": "sentinel-rs",
                    "protocol": protocol,
                    "ports_scanned": ports,
                    "open_ports": [],
                    "error": "Host unreachable or no ports found"
                }

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