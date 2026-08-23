from fastapi import APIRouter, Depends, HTTPException, Response, Query
from fastapi.security import OAuth2PasswordRequestForm
from app.models import UserCreate, Token, ScanRequest
from app.auth import hash_password, verify_password, create_access_token, get_current_user
from app.database import get_connection, save_scan_results, load_scan_results
from app.queue import enqueue_scan
from app.cve import search_cves, extract_services
import json
from datetime import datetime

router = APIRouter()

# --- AUTH ---

@router.post("/auth/register", status_code=201)
def register(user: UserCreate):
    conn = get_connection()
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (user.username,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Usuário já existe")
    hashed = hash_password(user.password)
    conn.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (user.username, hashed))
    conn.commit()
    conn.close()
    return {"message": "Usuário criado com sucesso"}

@router.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (form_data.username,)).fetchone()
    conn.close()
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    token = create_access_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}

# --- SCANS ---

@router.post("/scan", status_code=202)
def create_scan(scan: ScanRequest, current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO scans (user_id, targets, status, ports, protocol) VALUES (?, ?, ?, ?, ?)",
        (
            current_user["id"],
            json.dumps(scan.targets),
            "pending",
            scan.ports,
            scan.protocol,
        ),
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()

    try:
        job_id = enqueue_scan(scan_id, scan.targets, scan.ports, scan.protocol)
    except Exception as e:
        conn = get_connection()
        conn.execute("UPDATE scans SET status = ? WHERE id = ?", ("failed", scan_id))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=503, detail=f"Fila indisponível: {e}")

    return {
        "id": scan_id,
        "status": "pending",
        "job_id": job_id,
        "message": "Scan enfileirado. Consulte GET /scan/{id} para status.",
    }

@router.get("/scan/{scan_id}")
def get_scan(scan_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    scan = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, current_user["id"])
    ).fetchone()
    if not scan:
        conn.close()
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    results = load_scan_results(conn, scan_id)
    conn.close()
    return {
        "id": scan["id"],
        "targets": json.loads(scan["targets"]),
        "status": scan["status"],
        "results": results,
        "created_at": scan["created_at"]
    }

@router.delete("/scan/{scan_id}", status_code=200)
def delete_scan(scan_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    scan = conn.execute(
        "SELECT id FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, current_user["id"])
    ).fetchone()
    if not scan:
        conn.close()
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    conn.close()
    return {"message": f"Scan {scan_id} deletado com sucesso"}

@router.get("/scan/{scan_id}/report")
def get_scan_report(scan_id: int, format: str = "json", current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    scan = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, current_user["id"])
    ).fetchone()
    if not scan:
        conn.close()
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    results = load_scan_results(conn, scan_id)
    conn.close()

    if format == "csv":
        lines = ["target,port,service,status,protocol,error"]
        for r in results:
            if r["open_ports"]:
                for p in r["open_ports"]:
                    lines.append(f"{r['target']},{p['port']},{p['service']},{p['status']},{r.get('protocol','tcp')},")
            else:
                lines.append(f"{r['target']},,,,{r.get('protocol','tcp')},{r.get('error','')}")
        return Response(content="\n".join(lines), media_type="text/csv",
                       headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"})

    elif format == "markdown":
        lines = [f"# Scan Report #{scan_id}\n", "| Target | Port | Service | Status | Protocol |", "|---|---|---|---|---|"]
        for r in results:
            if r["open_ports"]:
                for p in r["open_ports"]:
                    lines.append(f"| {r['target']} | {p['port']} | {p['service']} | {p['status']} | {r.get('protocol','tcp')} |")
            else:
                lines.append(f"| {r['target']} | - | - | {r.get('error','no ports found')} | {r.get('protocol','tcp')} |")
        return Response(content="\n".join(lines), media_type="text/markdown",
                       headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.md"})

    return {
        "id": scan["id"],
        "targets": json.loads(scan["targets"]),
        "status": scan["status"],
        "results": results,
        "created_at": scan["created_at"]
    }

@router.get("/history")
def get_history(
    current_user: dict = Depends(get_current_user),
    page: int = Query(1, ge=1, description="Número da página"),
    limit: int = Query(10, ge=1, le=100, description="Itens por página")
):
    offset = (page - 1) * limit
    conn = get_connection()
    total = conn.execute(
        "SELECT COUNT(*) FROM scans WHERE user_id = ?",
        (current_user["id"],)
    ).fetchone()[0]
    scans = conn.execute(
        "SELECT id, targets, status, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (current_user["id"], limit, offset)
    ).fetchall()
    conn.close()
    return {
        "page": page,
        "limit": limit,
        "total": total,
        "pages": (total + limit - 1) // limit,
        "data": [
            {
                "id": s["id"],
                "targets": json.loads(s["targets"]),
                "status": s["status"],
                "created_at": s["created_at"]
            }
            for s in scans
        ]
    }

# --- USER ---

@router.get("/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "created_at": current_user["created_at"]
    }

# --- TRAPRS ALERTS ---

@router.post("/webhook/alert", status_code=200)
def receive_traprs_alert(payload: dict):
    received_at = datetime.utcnow().isoformat()
    src_ip = payload.get("src_ip")
    event_count = payload.get("event_count")
    window_secs = payload.get("window_secs")
    protocol = payload.get("protocol")

    conn = get_connection()
    cursor = conn.execute(
        """INSERT INTO alerts (src_ip, event_count, window_secs, protocol, payload, received_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (src_ip, event_count, window_secs, protocol, json.dumps(payload), received_at),
    )
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()

    print(f"[TrapRS ALERT] id={alert_id} src={src_ip} count={event_count} proto={protocol}")
    return {"status": "ok", "id": alert_id, "message": "Alerta recebido"}


@router.get("/alerts")
def list_alerts(
    current_user: dict = Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    offset = (page - 1) * limit
    conn = get_connection()
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    rows = conn.execute(
        """SELECT id, src_ip, event_count, window_secs, protocol, received_at
           FROM alerts ORDER BY received_at DESC LIMIT ? OFFSET ?""",
        (limit, offset),
    ).fetchall()
    conn.close()
    return {
        "page": page,
        "limit": limit,
        "total": total,
        "pages": (total + limit - 1) // limit if total else 0,
        "data": [
            {
                "id": r["id"],
                "src_ip": r["src_ip"],
                "event_count": r["event_count"],
                "window_secs": r["window_secs"],
                "protocol": r["protocol"],
                "received_at": r["received_at"],
            }
            for r in rows
        ],
    }

# --- CVE LOOKUP ---

@router.get("/cves")
def lookup_cves(
    service: str = Query(..., description="Nome do serviço/produto a buscar (ex: openssh, apache, log4j)"),
    limit: int = Query(10, ge=1, le=50, description="Número máximo de CVEs retornados"),
    days: int = Query(119, ge=1, le=119, description="Janela de dias para publicação (máx 119)")
):
    results = search_cves(service, limit, days)
    return {"service": service, "count": len(results), "cves": results}


@router.get("/scan/{scan_id}/cves")
def get_scan_cves(
    scan_id: int,
    limit: int = Query(5, ge=1, le=50, description="Número máximo de CVEs por serviço"),
    current_user: dict = Depends(get_current_user)
):
    conn = get_connection()
    scan = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, current_user["id"])
    ).fetchone()
    if not scan:
        conn.close()
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    results = load_scan_results(conn, scan_id)
    conn.close()

    services = extract_services(results)

    if not services:
        return {"scan_id": scan_id, "services": [], "cves": {}}

    cves_by_service = {
        service: search_cves(service, limit) for service in services
    }
    return {"scan_id": scan_id, "services": services, "cves": cves_by_service}
