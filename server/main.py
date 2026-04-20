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
from server.routes import agents, alerts, auth, health, snmp, security, logs, correlation, ws, devices, discovery, topology, reports, sigma
from shared.protocol import API_VERSION

SECURITY_SCAN_INTERVAL  = int(os.getenv("SECURITY_SCAN_INTERVAL", "60"))    # saniye
NTP_CHECK_INTERVAL      = int(os.getenv("NETGUARD_NTP_CHECK_INTERVAL", "300"))  # saniye (5 dk)
CORRELATION_INTERVAL    = int(os.getenv("NETGUARD_CORR_INTERVAL", "60"))    # saniye
DETECTOR_INTERVAL       = int(os.getenv("NETGUARD_DETECTOR_INTERVAL", "30")) # saniye
SNMP_POLL_INTERVAL      = int(os.getenv("NETGUARD_SNMP_INTERVAL", "60"))    # saniye
UPTIME_CHECK_INTERVAL   = int(os.getenv("NETGUARD_UPTIME_INTERVAL", "60"))  # saniye


async def _detector_loop():
    """Her DETECTOR_INTERVAL saniyede bir ağ saldırı dedektörlerini çalıştır."""
    from server.detectors.manager import detector_manager
    while True:
        await asyncio.sleep(DETECTOR_INTERVAL)
        try:
            logs = detector_manager.run_all()
            if logs:
                logger.warning(f"Dedektörler: {len(logs)} şüpheli olay")
        except Exception as exc:
            logger.error(f"Dedektör hatası: {exc}")


async def _correlation_loop():
    """Her CORRELATION_INTERVAL saniyede bir korelasyon motorunu çalıştır."""
    from server.correlator import correlator
    while True:
        await asyncio.sleep(CORRELATION_INTERVAL)
        try:
            events = correlator.run()
            if events:
                logger.warning(f"Korelasyon: {len(events)} yeni olay üretildi")
        except Exception as exc:
            logger.error(f"Korelasyon hatası: {exc}")


async def _ntp_check_loop():
    """Her NTP_CHECK_INTERVAL saniyede bir sistem saatini NTP ile karşılaştır."""
    from server.ntp_validator import ntp_validator
    while True:
        await asyncio.sleep(NTP_CHECK_INTERVAL)
        try:
            ntp_validator.check_system_clock()
        except Exception as exc:
            logger.error(f"NTP kontrol hatası: {exc}")


async def _snmp_poll_loop():
    """Her SNMP_POLL_INTERVAL saniyede bir kayıtlı SNMP cihazlarını sorgula."""
    from server.snmp_collector import poll_device_async
    from server.database import db

    while True:
        await asyncio.sleep(SNMP_POLL_INTERVAL)
        devices = db.get_snmp_devices(enabled_only=True)
        if not devices:
            continue
        try:
            results = await asyncio.gather(
                *[poll_device_async(d["host"], d["community"]) for d in devices],
                return_exceptions=True,
            )
            for info in results:
                if isinstance(info, Exception):
                    continue
                influx_writer.write_snmp(info)
                if not info.reachable:
                    logger.warning(f"SNMP erişilemiyor: {info.host}")
            reachable = sum(1 for r in results if not isinstance(r, Exception) and r.reachable)
            logger.debug(f"SNMP poll: {reachable}/{len(devices)} cihaz erişilebilir")
        except Exception as exc:
            logger.error(f"SNMP poll hatası: {exc}")


async def _uptime_check_loop():
    """Her UPTIME_CHECK_INTERVAL saniyede bir cihaz erişilebilirlik kontrolü yap."""
    from server.uptime_checker import uptime_checker
    while True:
        await asyncio.sleep(UPTIME_CHECK_INTERVAL)
        try:
            results = await uptime_checker.run_once()
            down = sum(1 for r in results if r["check_type"] == "icmp" and r["status"] == "down")
            if down:
                logger.warning(f"Uptime check: {down} cihaz erişilemiyor")
        except Exception as exc:
            logger.error(f"Uptime check hatası: {exc}")


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
    ntp_task  = asyncio.create_task(_ntp_check_loop())
    logger.info(f"NTP saat kontrolü başlatıldı (her {NTP_CHECK_INTERVAL}s)")
    corr_task = asyncio.create_task(_correlation_loop())
    logger.info(f"Korelasyon motoru başlatıldı (her {CORRELATION_INTERVAL}s)")
    detector_task = asyncio.create_task(_detector_loop())
    logger.info(f"Saldırı dedektörleri başlatıldı (her {DETECTOR_INTERVAL}s)")
    snmp_task = asyncio.create_task(_snmp_poll_loop())
    logger.info(f"SNMP polling döngüsü başlatıldı (her {SNMP_POLL_INTERVAL}s)")
    uptime_task = asyncio.create_task(_uptime_check_loop())
    logger.info(f"Uptime checker başlatıldı (her {UPTIME_CHECK_INTERVAL}s)")
    from server.syslog_receiver import SyslogReceiver
    syslog = SyslogReceiver()
    await syslog.start()
    from server.snmp_trap_receiver import SNMPTrapReceiver
    trap_receiver = SNMPTrapReceiver()
    await trap_receiver.start()
    yield
    scan_task.cancel()
    ntp_task.cancel()
    corr_task.cancel()
    detector_task.cancel()
    snmp_task.cancel()
    uptime_task.cancel()
    syslog.stop()
    trap_receiver.stop()
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
_cors_default = ",".join([
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://192.168.203.134:3000",
    "http://192.168.203.142:3000",
    "http://192.168.1.113:3000",
    "http://192.168.203.1:3000",
])
_cors_origins = [o.strip() for o in os.getenv("NETGUARD_CORS_ORIGINS", _cors_default).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key"],
)

api_prefix = f"/api/{API_VERSION}"
app.include_router(health.router, prefix=api_prefix, tags=["health"])
app.include_router(auth.router, prefix=api_prefix, tags=["auth"])
app.include_router(agents.router, prefix=api_prefix, tags=["agents"])
app.include_router(alerts.router, prefix=api_prefix, tags=["alerts"])
app.include_router(snmp.router, prefix=api_prefix, tags=["snmp"])
app.include_router(security.router, prefix=api_prefix, tags=["security"])
app.include_router(logs.router,        prefix=api_prefix, tags=["logs"])
app.include_router(correlation.router, prefix=api_prefix, tags=["correlation"])
app.include_router(devices.router, prefix=api_prefix, tags=["devices"])
app.include_router(discovery.router, prefix=api_prefix, tags=["discovery"])
app.include_router(topology.router, prefix=api_prefix, tags=["topology"])
app.include_router(reports.router,  prefix=api_prefix, tags=["reports"])
app.include_router(sigma.router,    prefix=api_prefix, tags=["sigma"])
app.include_router(ws.router, tags=["websocket"])


@app.get("/")
def root():
    return {
        "name": "NetGuard Server",
        "version": "0.1.0",
        "api": api_prefix,
        "docs": "/docs",
    }