from fastapi import FastAPI
from app.database import init_db
from app.routes import router

app = FastAPI(
    title="Netwatch API",
    description="API de scanning de rede com autenticação JWT",
    version="1.0.0"
)

@app.on_event("startup")
def startup():
    init_db()

app.include_router(router)

@app.get("/")
def root():
    return {"message": "Netwatch API online", "docs": "/docs"}
