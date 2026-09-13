from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.api.dashboard import router as dashboard_router
from app.api.incidents import router as incidents_router
from app.api.tools import router as tools_router
from app.memory.database import init_db


app = FastAPI(
    title="Sentinel SOC",
    description="Autonomous SOC Investigation and Response Platform",
    version="1.0.0",
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

@app.on_event("startup")
def startup() -> None:
    init_db()


# ============================================================
# STATIC FILES
# ============================================================

app.mount(
    "/static",
    StaticFiles(
        directory="app/ui/static"
    ),
    name="static",
)


# ============================================================
# API ROUTERS
# ============================================================

app.include_router(
    incidents_router
)

app.include_router(
    dashboard_router
)

app.include_router(
    tools_router
)


# ============================================================
# DASHBOARD
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse,
)
def root() -> str:

    template_path = Path(
        "app/ui/templates/dashboard.html"
    )

    if not template_path.exists():
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sentinel SOC</title>
        </head>
        <body>
            <h1>Sentinel SOC</h1>
            <p>Dashboard template not found.</p>
        </body>
        </html>
        """

    return template_path.read_text(
        encoding="utf-8"
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "service": "sentinel-soc",
    }