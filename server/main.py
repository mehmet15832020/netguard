"""
NetGuard Server — Ana uygulama
"""

import asyncio
import logging
import os
import socket
from contextlib import asynccontextmanager
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from server.influx_writer import influx_writer
from server.routes import agents, alerts, auth, health, snmp, security, logs
from shared.protocol import API_VERSION

SECURITY_SCAN_INTERVAL = int(os.getenv("SECURITY_SCAN_INTERVAL", "60"))  # saniye
NTP_CHECK_INTERVAL     = int(os.getenv("NETGUARD_NTP_CHECK_INTERVAL", "300"))  # saniye (5 dk)


async def _ntp_check_loop():
    """Her NTP_CHECK_INTERVAL saniyede bir sistem saatini NTP ile karşılaştır."""
    from server.ntp_validator import ntp_validator
    while True:
        await asyncio.sleep(NTP_CHECK_INTERVAL)
        try:
            ntp_validator.check_system_clock()
        except Exception as exc:
            logger.error(f"NTP kontrol hatası: {exc}")


async def _security_scan_loop():
    """Her SECURITY_SCAN_INTERVAL saniyede bir güvenlik taraması yap."""
    from server.security_log_parser import parse_auth_log
    from server.port_monitor import port_monitor
    from server.config_monitor import config_monitor

    agent_id = os.getenv("AGENT_ID", socket.gethostname())

    while True:
        await asyncio.sleep(SECURITY_SCAN_INTERVAL)
        try:
            parse_auth_log(agent_id=agent_id)
            port_monitor.check(agent_id=agent_id)
            config_monitor.check(agent_id=agent_id)
        except Exception as exc:
            logger.error(f"Güvenlik tarama hatası: {exc}")


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
    scan_task = asyncio.create_task(_security_scan_loop())
    logger.info(f"Güvenlik tarama döngüsü başlatıldı (her {SECURITY_SCAN_INTERVAL}s)")
    ntp_task = asyncio.create_task(_ntp_check_loop())
    logger.info(f"NTP saat kontrolü başlatıldı (her {NTP_CHECK_INTERVAL}s)")
    from server.syslog_receiver import SyslogReceiver
    syslog = SyslogReceiver()
    await syslog.start()
    yield
    scan_task.cancel()
    ntp_task.cancel()
    syslog.stop()
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
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://192.168.203.134:3000",  # VM1 - NetGuard Server
        "http://192.168.203.142:3000",  # VM2 - Agent
        "http://192.168.1.113:3000",    # Ana makine
        "http://192.168.203.1:3000",    # VMware ağı gateway
    ],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

api_prefix = f"/api/{API_VERSION}"
app.include_router(health.router, prefix=api_prefix, tags=["health"])
app.include_router(auth.router, prefix=api_prefix, tags=["auth"])
app.include_router(agents.router, prefix=api_prefix, tags=["agents"])
app.include_router(alerts.router, prefix=api_prefix, tags=["alerts"])
app.include_router(snmp.router, prefix=api_prefix, tags=["snmp"])
app.include_router(security.router, prefix=api_prefix, tags=["security"])
app.include_router(logs.router,    prefix=api_prefix, tags=["logs"])


@app.get("/")
def root():
    return {
        "name": "NetGuard Server",
        "version": "0.1.0",
        "api": api_prefix,
        "docs": "/docs",
    }