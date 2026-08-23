import json
from app.database import get_connection, save_scan_results
from app.scanner import run_sentinel


def process_scan(scan_id: int, targets: list, ports: str, protocol: str):
    """Job RQ: executa o scan e atualiza o banco."""
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE scans SET status = ? WHERE id = ?",
            ("running", scan_id),
        )
        conn.commit()

        results = run_sentinel(targets, ports, protocol)

        conn.execute(
            "UPDATE scans SET status = ?, results = ? WHERE id = ?",
            ("completed", json.dumps(results), scan_id),
        )
        save_scan_results(conn, scan_id, results)
        conn.commit()
        return {"scan_id": scan_id, "status": "completed", "hosts": len(results)}
    except Exception as e:
        conn.execute(
            "UPDATE scans SET status = ?, results = ? WHERE id = ?",
            ("failed", json.dumps({"error": str(e)}), scan_id),
        )
        conn.commit()
        raise
    finally:
        conn.close()
