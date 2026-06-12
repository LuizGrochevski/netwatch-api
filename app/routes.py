from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.security import OAuth2PasswordRequestForm
from app.models import UserCreate, Token, ScanRequest
from app.auth import hash_password, verify_password, create_access_token, get_current_user
from app.database import get_connection
from app.scanner import run_sentinel
import json

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
    results = run_sentinel(scan.targets, scan.ports, scan.protocol)
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO scans (user_id, targets, status, results) VALUES (?, ?, ?, ?)",
        (current_user["id"], json.dumps(scan.targets), "completed", json.dumps(results))
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"id": scan_id, "status": "completed", "results": results}

@router.get("/scan/{scan_id}")
def get_scan(scan_id: int, current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    scan = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, current_user["id"])
    ).fetchone()
    conn.close()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    return {
        "id": scan["id"],
        "targets": json.loads(scan["targets"]),
        "status": scan["status"],
        "results": json.loads(scan["results"]),
        "created_at": scan["created_at"]
    }

@router.get("/scan/{scan_id}/report")
def get_scan_report(scan_id: int, format: str = "json", current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    scan = conn.execute(
        "SELECT * FROM scans WHERE id = ? AND user_id = ?",
        (scan_id, current_user["id"])
    ).fetchone()
    conn.close()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan não encontrado")

    results = json.loads(scan["results"])

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
def get_history(current_user: dict = Depends(get_current_user)):
    conn = get_connection()
    scans = conn.execute(
        "SELECT id, targets, status, created_at FROM scans WHERE user_id = ? ORDER BY created_at DESC",
        (current_user["id"],)
    ).fetchall()
    conn.close()
    return [
        {
            "id": s["id"],
            "targets": json.loads(s["targets"]),
            "status": s["status"],
            "created_at": s["created_at"]
        }
        for s in scans
    ]

# --- USER ---

@router.get("/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "created_at": current_user["created_at"]
    }
