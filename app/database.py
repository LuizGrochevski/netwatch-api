import sqlite3
import json
from datetime import datetime

DB_PATH = "netwatch.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def _column_exists(cursor, table: str, column: str) -> bool:
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cursor.fetchall())

def migrate(conn):
    """Adiciona colunas/tabelas faltantes em DBs antigos."""
    cursor = conn.cursor()

    if not _column_exists(cursor, "scans", "ports"):
        cursor.execute("ALTER TABLE scans ADD COLUMN ports TEXT")
    if not _column_exists(cursor, "scans", "protocol"):
        cursor.execute("ALTER TABLE scans ADD COLUMN protocol TEXT DEFAULT 'tcp'")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS host_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            target TEXT NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            ports_scanned TEXT,
            error TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS open_ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_result_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            service TEXT,
            produto TEXT,
            versao TEXT,
            status TEXT,
            FOREIGN KEY (host_result_id) REFERENCES host_results(id) ON DELETE CASCADE
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            severity TEXT,
            published TEXT,
            description TEXT,
            fetched_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(keyword, cve_id)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT,
            event_count INTEGER,
            window_secs INTEGER,
            protocol TEXT,
            payload TEXT,
            received_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_host_results_scan ON host_results(scan_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_open_ports_host ON open_ports(host_result_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cve_cache_keyword ON cve_cache(keyword)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_received ON alerts(received_at DESC)")
    conn.commit()

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            targets TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            ports TEXT,
            protocol TEXT DEFAULT 'tcp',
            results TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    migrate(conn)
    conn.close()


def save_scan_results(conn, scan_id: int, results: list):
    """Persiste results normalizados em host_results + open_ports."""
    for r in results:
        cur = conn.execute(
            """INSERT INTO host_results (scan_id, target, protocol, ports_scanned, error)
               VALUES (?, ?, ?, ?, ?)""",
            (
                scan_id,
                r.get("target"),
                r.get("protocol", "tcp"),
                r.get("ports_scanned"),
                r.get("error"),
            ),
        )
        host_id = cur.lastrowid
        for p in r.get("open_ports") or []:
            conn.execute(
                """INSERT INTO open_ports (host_result_id, port, service, produto, versao, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    host_id,
                    p.get("port"),
                    p.get("service"),
                    p.get("produto"),
                    p.get("versao"),
                    p.get("status"),
                ),
            )


def load_scan_results(conn, scan_id: int) -> list:
    """Reconstrói a lista de results a partir das tabelas normalizadas.
    Fallback para JSON legado se host_results estiver vazio.
    """
    hosts = conn.execute(
        "SELECT * FROM host_results WHERE scan_id = ? ORDER BY id",
        (scan_id,),
    ).fetchall()

    if not hosts:
        row = conn.execute("SELECT results FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row and row["results"]:
            return json.loads(row["results"])
        return []

    results = []
    for h in hosts:
        ports = conn.execute(
            "SELECT port, service, produto, versao, status FROM open_ports WHERE host_result_id = ?",
            (h["id"],),
        ).fetchall()
        results.append({
            "target": h["target"],
            "engine": "sentinel-rs",
            "protocol": h["protocol"] or "tcp",
            "ports_scanned": h["ports_scanned"],
            "open_ports": [
                {
                    "port": p["port"],
                    "service": p["service"],
                    "produto": p["produto"],
                    "versao": p["versao"],
                    "status": p["status"],
                }
                for p in ports
            ],
            "error": h["error"],
        })
    return results
