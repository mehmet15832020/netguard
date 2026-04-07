"""
NetGuard Server — Ana uygulama
"""

import logging
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from server.influx_writer import influx_writer
from server.routes import agents, alerts, auth, health
from shared.protocol import API_VERSION
from server.routes import agents, alerts, auth, health, snmp


load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("netguard.server")

# Rate limiter
limiter = Limiter(key_func=get_remote_address)




@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=" * 50)
    logger.info("NetGuard Server başlatılıyor...")
    logger.info(f"API versiyonu: {API_VERSION}")
    logger.info("=" * 50)
    influx_writer.connect()
    yield
    influx_writer.close()
    logger.info("NetGuard Server kapatılıyor...")


app = FastAPI(
    title="NetGuard Server",
    description="Modüler ağ izleme ve güvenlik monitoring sistemi",
    version="0.1.0",
    lifespan=lifespan,
)

# Rate limiter middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

api_prefix = f"/api/{API_VERSION}"
app.include_router(health.router, prefix=api_prefix, tags=["health"])
app.include_router(auth.router, prefix=api_prefix, tags=["auth"])
app.include_router(agents.router, prefix=api_prefix, tags=["agents"])
app.include_router(alerts.router, prefix=api_prefix, tags=["alerts"])


@app.get("/")
def root():
    return {
        "name": "NetGuard Server",
        "version": "0.1.0",
        "api": api_prefix,
        "docs": "/docs",
    }

app.include_router(snmp.router, prefix=api_prefix, tags=["snmp"])