from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.database import init_db
from app.routes import router

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(
    title="Netwatch API",
    description="API de scanning de rede com autenticação JWT",
    version="1.0.0",
    lifespan=lifespan
)

app.include_router(router)

@app.get("/")
def root():
    return {
        "name": "Netwatch API",
        "version": "1.0.0",
        "status": "online",
        "engine": "sentinel-rs",
        "docs": "/docs",
        "endpoints": {
            "auth": ["/auth/register", "/auth/login"],
            "user": ["/me"],
            "scan": ["/scan", "/scan/{id}", "/scan/{id}/report"],
            "history": ["/history"]
        },
        "usage": {
            "1_register": "POST /auth/register",
            "2_login": "POST /auth/login",
            "3_scan": "POST /scan {targets, ports, protocol}",
            "4_report": "GET /scan/{id}/report?format=csv|markdown"
        }
    }
