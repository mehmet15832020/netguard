"""
B3 — server/syslog_receiver.py testleri.

SyslogFrameParser: RFC 6587 octet-counting + LF-delimited framing.
SyslogTCPReceiver: gerçek TCP/TLS bağlantı üzerinden process_and_store çağrımı.

pytest-asyncio kurulu değil — async senaryolar asyncio.run() ile sarılmış
sync test fonksiyonlarında çalıştırılır (bkz. test_file_watch.py, S1).
"""

import asyncio
import ssl

import pytest

from server.syslog_receiver import (
    SyslogFrameParser,
    SyslogTCPReceiver,
)


# ── SyslogFrameParser — LF-delimited ───────────────────────────────────────

class TestLfDelimitedFraming:
    def test_single_message(self):
        parser = SyslogFrameParser()
        msgs = parser.feed(b"<34>1 2024-01-01T00:00:00Z host app - - - test message\n")
        assert msgs == ["<34>1 2024-01-01T00:00:00Z host app - - - test message"]

    def test_multiple_messages_in_one_feed(self):
        parser = SyslogFrameParser()
        msgs = parser.feed(b"<34>first msg\n<35>second msg\n")
        assert msgs == ["<34>first msg", "<35>second msg"]

    def test_partial_message_across_two_feeds(self):
        parser = SyslogFrameParser()
        assert parser.feed(b"<34>partial ") == []
        assert parser.feed(b"message\n") == ["<34>partial message"]

    def test_no_trailing_newline_yields_nothing_yet(self):
        parser = SyslogFrameParser()
        assert parser.feed(b"<34>incomplete") == []

    def test_crlf_stripped(self):
        parser = SyslogFrameParser()
        msgs = parser.feed(b"<34>windows style\r\n")
        assert msgs == ["<34>windows style"]

    def test_oversized_message_buffer_cleared(self):
        parser = SyslogFrameParser(max_frame_bytes=100)
        msgs = parser.feed(b"<34>" + b"a" * 200)  # LF yok, limit aşıldı
        assert msgs == []
        assert len(parser._buffer) == 0


# ── SyslogFrameParser — Octet-counting (RFC 6587 §3.4.1) ───────────────────

class TestOctetCountingFraming:
    def test_single_message(self):
        msg = "<34>1 2024-01-01T00:00:00Z host app - - - test"
        frame = f"{len(msg)} {msg}".encode()
        parser = SyslogFrameParser()
        assert parser.feed(frame) == [msg]

    def test_message_containing_embedded_newline(self):
        """Octet-counting'in asıl avantajı: mesaj içindeki \\n LF-delimited'i kırmaz."""
        msg = "<34>line1\nline2 still same message"
        frame = f"{len(msg)} {msg}".encode()
        parser = SyslogFrameParser()
        assert parser.feed(frame) == [msg]

    def test_multiple_messages_in_one_feed(self):
        msg1, msg2 = "<34>first", "<35>second one"
        frame = f"{len(msg1)} {msg1}{len(msg2)} {msg2}".encode()
        parser = SyslogFrameParser()
        assert parser.feed(frame) == [msg1, msg2]

    def test_partial_frame_split_before_length_complete(self):
        msg = "<34>hello world"
        full = f"{len(msg)} {msg}".encode()
        parser = SyslogFrameParser()
        assert parser.feed(full[:1]) == []   # sadece "1" (length'in ilk hanesi)
        assert parser.feed(full[1:]) == [msg]

    def test_partial_frame_split_mid_message(self):
        msg = "<34>hello world, this is a longer message body"
        full = f"{len(msg)} {msg}".encode()
        split = len(str(len(msg))) + 1 + 5  # length+SP+5 byte mesaj
        parser = SyslogFrameParser()
        assert parser.feed(full[:split]) == []
        assert parser.feed(full[split:]) == [msg]

    def test_zero_length_skipped(self):
        parser = SyslogFrameParser()
        assert parser.feed(b"0 <34>next") == []

    def test_excessive_length_skipped(self):
        parser = SyslogFrameParser(max_frame_bytes=10)
        assert parser.feed(b"99999 ") == []

    def test_octet_counting_then_lf_delimited_mixed(self):
        msg1 = "<34>octet counted"
        frame = f"{len(msg1)} {msg1}".encode() + b"<35>lf delimited\n"
        parser = SyslogFrameParser()
        assert parser.feed(frame) == [msg1, "<35>lf delimited"]


# ── SyslogTCPReceiver — gerçek bağlantı üzerinden ──────────────────────────

class TestSyslogTcpReceiverPlain:
    def test_receives_lf_delimited_message(self, monkeypatch):
        import server.syslog_receiver as sr
        received = []
        monkeypatch.setattr(sr, "process_and_store", lambda content, host: received.append((content, host)))

        async def scenario():
            receiver = SyslogTCPReceiver(host="127.0.0.1", port=0)
            await receiver.start()
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", receiver.port)
                writer.write(b"<34>1 2024-01-01T00:00:00Z testhost app - - - hello via tcp\n")
                await writer.drain()
                writer.close()
                for _ in range(40):
                    if received:
                        break
                    await asyncio.sleep(0.05)
            finally:
                receiver.stop()
            return received

        result = asyncio.run(scenario())
        assert len(result) == 1
        assert "hello via tcp" in result[0][0]
        assert result[0][1] == "127.0.0.1"

    def test_receives_multiple_messages_one_connection(self, monkeypatch):
        import server.syslog_receiver as sr
        received = []
        monkeypatch.setattr(sr, "process_and_store", lambda content, host: received.append(content))

        async def scenario():
            receiver = SyslogTCPReceiver(host="127.0.0.1", port=0)
            await receiver.start()
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", receiver.port)
                writer.write(b"<34>first\n<35>second\n<36>third\n")
                await writer.drain()
                writer.close()
                for _ in range(40):
                    if len(received) >= 3:
                        break
                    await asyncio.sleep(0.05)
            finally:
                receiver.stop()
            return received

        result = asyncio.run(scenario())
        assert len(result) == 3

    def test_tls_not_started_without_cert(self):
        async def scenario():
            receiver = SyslogTCPReceiver(host="127.0.0.1", port=0, tls_cert=None, tls_key=None)
            await receiver.start()
            tls_port = receiver.tls_port
            receiver.stop()
            return tls_port

        assert asyncio.run(scenario()) is None


class TestSyslogTcpReceiverTls:
    @pytest.fixture
    def self_signed_cert(self, tmp_path):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime as dt

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        cert_path = tmp_path / "cert.pem"
        key_path = tmp_path / "key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        return cert_path, key_path

    def test_tls_receiver_accepts_encrypted_connection(self, self_signed_cert, monkeypatch):
        import server.syslog_receiver as sr
        cert_path, key_path = self_signed_cert
        received = []
        monkeypatch.setattr(sr, "process_and_store", lambda content, host: received.append(content))

        async def scenario():
            receiver = SyslogTCPReceiver(
                host="127.0.0.1", port=0, tls_port=0,
                tls_cert=str(cert_path), tls_key=str(key_path),
            )
            await receiver.start()
            assert receiver.tls_port is not None
            try:
                client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client_ctx.check_hostname = False
                client_ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", receiver.tls_port, ssl=client_ctx,
                )
                writer.write(b"<34>tls encrypted message\n")
                await writer.drain()
                writer.close()
                for _ in range(40):
                    if received:
                        break
                    await asyncio.sleep(0.05)
            finally:
                receiver.stop()
            return received

        result = asyncio.run(scenario())
        assert len(result) == 1
        assert "tls encrypted message" in result[0]
