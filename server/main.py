"""
NetGuard Server — Ana uygulama

FastAPI uygulamasını başlatır, router'ları bağlar,
startup/shutdown olaylarını yönetir.
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from server.routes import agents, health
from shared.protocol import API_VERSION

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("netguard.server")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Server başlangıç ve kapanış olayları."""
    logger.info("=" * 50)
    logger.info("NetGuard Server başlatılıyor...")
    logger.info(f"API versiyonu: {API_VERSION}")
    logger.info("=" * 50)
    yield
    logger.info("NetGuard Server kapatılıyor...")


app = FastAPI(
    title="NetGuard Server",
    description="Modüler ağ izleme ve güvenlik monitoring sistemi",
    version="0.1.0",
    lifespan=lifespan,
)

# Router'ları bağla
api_prefix = f"/api/{API_VERSION}"
app.include_router(health.router, prefix=api_prefix, tags=["health"])
app.include_router(agents.router, prefix=api_prefix, tags=["agents"])


@app.get("/")
def root():
    return {
        "name": "NetGuard Server",
        "version": "0.1.0",
        "api": api_prefix,
        "docs": "/docs",
    }