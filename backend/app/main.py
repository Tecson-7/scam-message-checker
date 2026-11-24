from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import db
from .config import settings
from .routers import check


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()          # creates tables on Neon the first time
    yield


app = FastAPI(title="Scam Message Checker", version="0.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    # Vite dev server on either hostname + the deployed frontend (FRONTEND_ORIGIN in .env)
    allow_origins=list({settings.frontend_origin, "http://localhost:5173", "http://127.0.0.1:5173"}),
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(check.router)


@app.get("/health")
def health():
    return {"status": "ok", "database": db.ready, "safe_browsing_key": bool(settings.safe_browsing_key)}
