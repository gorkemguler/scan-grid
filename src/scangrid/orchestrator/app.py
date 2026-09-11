"""FastAPI application factory for the orchestrator."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..allowlist import _allow_networks
from ..config import get_settings
from ..db import init_db
from .enrich import enrich_batch
from .housekeeping import enqueue_due_targets, notify_pending_changes, prune_history
from .routes_api import router as api_router
from .routes_dashboard import router as dashboard_router
from .routes_worker import router as worker_router

log = logging.getLogger("scangrid.orchestrator")
_HERE = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    init_db()
    # Fail fast + loud if the allowlist is unusable.
    nets = _allow_networks()
    log.info("orchestrator v%s; allowlist: %s", __version__, [str(n) for n in nets])

    sched = BackgroundScheduler(timezone="UTC")
    sched.add_job(enqueue_due_targets, "interval", seconds=60, id="enqueue", max_instances=1)
    sched.add_job(enrich_batch, "interval", seconds=45, id="enrich", max_instances=1)
    sched.add_job(notify_pending_changes, "interval", seconds=30, id="notify", max_instances=1)
    sched.add_job(prune_history, "interval", hours=6, id="prune", max_instances=1)
    sched.start()
    app.state.scheduler = sched
    try:
        yield
    finally:
        sched.shutdown(wait=False)
        log.info("orchestrator stopped")


def create_app() -> FastAPI:
    app = FastAPI(
        title="ScanGrid Orchestrator",
        version=__version__,
        summary="Job queue, asset inventory, CVE matching and dashboard for ScanGrid workers.",
        lifespan=lifespan,
    )
    app.include_router(api_router)
    app.include_router(worker_router)
    app.include_router(dashboard_router)
    app.mount("/static", StaticFiles(directory=_HERE / "static"), name="static")
    return app


app = create_app()
