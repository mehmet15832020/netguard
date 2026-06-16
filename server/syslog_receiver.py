"""
NetGuard — Syslog Receiver

UDP 5140 portunu dinler (root gerektirmeyen standart dışı port).
Ayrıca RFC 6587 (TCP) ve RFC 5425 (TLS) syslog alıcıları — UDP yoğun
trafikte sessizce paket düşürebildiği için (B3) güvenilir teslimat
gerektiren kaynaklar (OPNsense/VyOS) TCP/TLS'e yönlendirilebilir.
UDP eski/basit cihazlar için varsayılan olarak açık kalır.

Gelen her syslog mesajını log_normalizer üzerinden işler.

Başlatmak için:
    receiver = SyslogReceiver()
    await receiver.start()
    tcp_receiver = SyslogTCPReceiver()
    await tcp_receiver.start()
"""

import asyncio
import logging
import os
from typing import Optional

from server.log_normalizer import process_and_store

logger = logging.getLogger(__name__)

SYSLOG_HOST = os.getenv("NETGUARD_SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT = int(os.getenv("NETGUARD_SYSLOG_PORT", "5140"))

# RFC 6587 TCP syslog — IANA standart portu 601 (root gerektirir),
# UDP 514→5140 dönüşümüyle aynı mantıkla 601→6010 (root gerektirmez).
SYSLOG_TCP_PORT = int(os.getenv("NETGUARD_SYSLOG_TCP_PORT", "6010"))
# RFC 5425 TLS syslog — IANA standart portu 6514, zaten >1024.
SYSLOG_TLS_PORT = int(os.getenv("NETGUARD_SYSLOG_TLS_PORT", "6514"))
SYSLOG_TLS_CERT = os.getenv("NETGUARD_SYSLOG_TLS_CERT")
SYSLOG_TLS_KEY  = os.getenv("NETGUARD_SYSLOG_TLS_KEY")
SYSLOG_MAX_FRAME_BYTES = int(os.getenv("NETGUARD_SYSLOG_MAX_FRAME_BYTES", str(64 * 1024)))


class _SyslogProtocol(asyncio.DatagramProtocol):
    """asyncio UDP protokolü — her gelen datagram bir log mesajı."""

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        observer_hostname = addr[0]
        try:
            raw_content = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return

        if not raw_content:
            return

        try:
            process_and_store(raw_content, observer_hostname)
        except Exception as exc:
            logger.error(f"Syslog işleme hatası ({observer_hostname}): {exc}")

    def error_received(self, exc: Exception) -> None:
        logger.error(f"Syslog UDP hatası: {exc}")

    def connection_lost(self, exc: Exception) -> None:
        if exc:
            logger.warning(f"Syslog bağlantısı kesildi: {exc}")


class SyslogReceiver:
    """UDP syslog alıcısı."""

    def __init__(
        self,
        host: str = SYSLOG_HOST,
        port: int = SYSLOG_PORT,
    ):
        self._host = host
        self._port = port
        self._transport = None

    async def start(self) -> None:
        """UDP dinlemeyi başlat."""
        import socket
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind((self._host, self._port))
        self._transport, _ = await loop.create_datagram_endpoint(
            _SyslogProtocol,
            sock=sock,
        )
        logger.info(f"Syslog alıcısı başlatıldı: UDP {self._host}:{self._port}")

    def stop(self) -> None:
        """UDP dinlemeyi durdur."""
        if self._transport:
            self._transport.close()
            logger.info("Syslog alıcısı durduruldu.")


class SyslogFrameParser:
    """
    RFC 6587 §3.4 — TCP üzerinden gelen byte akışından syslog mesajlarını ayırır.

    İki framing yöntemi desteklenir, ilk byte'a göre otomatik seçilir:
      - Octet-counting (§3.4.1): "MSGLEN SP SYSLOG-MSG" — MSGLEN tam byte sayısı.
        Mesaj içinde LF olsa da güvenli ayrıştırma sağlar.
      - Non-transparent-framing (§3.4.2, LF-delimited): geleneksel rsyslog "@@"
        TCP forwarding davranışı — mesajlar '\\n' ile ayrılır.

    Tek bir TCP read() çağrısı birden fazla veya kısmi mesaj içerebilir;
    bu sınıf bağlantı ömrü boyunca state (buffer) taşır.
    """

    def __init__(self, max_frame_bytes: int = SYSLOG_MAX_FRAME_BYTES):
        self._buffer = bytearray()
        self._max_frame_bytes = max_frame_bytes

    def feed(self, data: bytes) -> list[str]:
        """Yeni gelen byte'ları buffer'a ekler, çıkarılabilen tüm mesajları döndürür."""
        self._buffer.extend(data)
        messages = []
        while True:
            msg = self._try_extract_one()
            if msg is None:
                break
            messages.append(msg)
        return messages

    def _try_extract_one(self) -> Optional[str]:
        if not self._buffer:
            return None
        if chr(self._buffer[0]).isdigit():
            return self._try_extract_octet_counted()
        return self._try_extract_lf_delimited()

    def _try_extract_octet_counted(self) -> Optional[str]:
        sp_idx = self._buffer.find(b" ")
        if sp_idx == -1:
            if len(self._buffer) > 10:  # makul bir uzunluk alanı 10 hane'yi aşmaz
                logger.warning("Syslog TCP: octet-counting ayraç (SP) bulunamadı, LF moduna düşülüyor")
                return self._try_extract_lf_delimited()
            return None  # henüz SP gelmedi, daha fazla veri bekleniyor

        length_field = bytes(self._buffer[:sp_idx])
        if not length_field.isdigit():
            return self._try_extract_lf_delimited()

        msg_len = int(length_field)
        if msg_len <= 0 or msg_len > self._max_frame_bytes:
            logger.warning(f"Syslog TCP: geçersiz/aşırı büyük frame uzunluğu ({msg_len}), atlanıyor")
            del self._buffer[:sp_idx + 1]
            return None

        total_needed = sp_idx + 1 + msg_len
        if len(self._buffer) < total_needed:
            return None  # mesajın tamamı henüz gelmedi

        msg_bytes = bytes(self._buffer[sp_idx + 1: total_needed])
        del self._buffer[:total_needed]
        return msg_bytes.decode("utf-8", errors="replace")

    def _try_extract_lf_delimited(self) -> Optional[str]:
        nl_idx = self._buffer.find(b"\n")
        if nl_idx == -1:
            if len(self._buffer) > self._max_frame_bytes:
                logger.warning("Syslog TCP: LF-delimited mesaj boyut limitini aştı, buffer temizlendi")
                self._buffer.clear()
            return None
        line = bytes(self._buffer[:nl_idx])
        del self._buffer[:nl_idx + 1]
        return line.rstrip(b"\r").decode("utf-8", errors="replace")


async def _handle_syslog_tcp_connection(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
) -> None:
    peer = writer.get_extra_info("peername")
    observer_hostname = peer[0] if peer else "unknown"
    parser = SyslogFrameParser()
    try:
        while True:
            data = await reader.read(8192)
            if not data:
                break
            for message in parser.feed(data):
                message = message.strip()
                if not message:
                    continue
                try:
                    process_and_store(message, observer_hostname)
                except Exception as exc:
                    logger.error(f"Syslog TCP işleme hatası ({observer_hostname}): {exc}")
    except (ConnectionResetError, asyncio.IncompleteReadError) as exc:
        logger.debug(f"Syslog TCP bağlantı kapandı ({observer_hostname}): {exc}")
    except Exception as exc:
        logger.warning(f"Syslog TCP bağlantı hatası ({observer_hostname}): {exc}")
    finally:
        writer.close()


class SyslogTCPReceiver:
    """
    RFC 6587 (TCP) + opsiyonel RFC 5425 (TLS) syslog alıcısı.

    UDP'nin tamamlayıcısıdır — TCP'nin transport katmanı garantili teslimat
    sağladığı için yoğun trafikte sessiz paket kaybı riski olmaz (B3).
    TLS sertifikası tanımlı değilse TLS portu açılmaz, sadece düz TCP dinlenir.
    """

    def __init__(
        self,
        host: str = SYSLOG_HOST,
        port: int = SYSLOG_TCP_PORT,
        tls_port: int = SYSLOG_TLS_PORT,
        tls_cert: Optional[str] = SYSLOG_TLS_CERT,
        tls_key: Optional[str] = SYSLOG_TLS_KEY,
    ):
        self._host = host
        self._port = port
        self._tls_port = tls_port
        self._tls_cert = tls_cert
        self._tls_key = tls_key
        self._server: Optional[asyncio.AbstractServer] = None
        self._tls_server: Optional[asyncio.AbstractServer] = None

    @property
    def port(self) -> Optional[int]:
        if self._server is None:
            return None
        return self._server.sockets[0].getsockname()[1]

    @property
    def tls_port(self) -> Optional[int]:
        if self._tls_server is None:
            return None
        return self._tls_server.sockets[0].getsockname()[1]

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            _handle_syslog_tcp_connection, self._host, self._port,
        )
        logger.info(f"Syslog alıcısı başlatıldı: TCP {self._host}:{self.port} (RFC 6587)")

        if self._tls_cert and self._tls_key:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self._tls_cert, self._tls_key)
            self._tls_server = await asyncio.start_server(
                _handle_syslog_tcp_connection, self._host, self._tls_port, ssl=ctx,
            )
            logger.info(f"Syslog alıcısı başlatıldı: TLS {self._host}:{self.tls_port} (RFC 5425)")
        else:
            logger.info(
                "NETGUARD_SYSLOG_TLS_CERT/NETGUARD_SYSLOG_TLS_KEY tanımlı değil — "
                "syslog TLS alıcısı (6514) devre dışı, sadece düz TCP aktif"
            )

    def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            logger.info("Syslog TCP alıcısı durduruldu.")
        if self._tls_server is not None:
            self._tls_server.close()
            logger.info("Syslog TLS alıcısı durduruldu.")
