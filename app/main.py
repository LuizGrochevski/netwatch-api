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
    return {"message": "Netwatch API online", "docs": "/docs"}
