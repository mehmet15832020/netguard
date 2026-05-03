#!/usr/bin/env python3
"""
NetGuard Lab Başlatıcı
GNS3 açıldıktan sonra bu scripti çalıştır.
Alpine WebServer'ı otomatik olarak yapılandırır.
"""

import json
import socket
import sys
import time
import urllib.request
import urllib.error
import base64
import pexpect

GNS3_URL = "http://127.0.0.1:3080/v2"
GNS3_USER = "admin"
GNS3_PASS = "KLMwSeS0mklkToRm5EAWuhBgumnr0HHrD2ezvIVikaeDy3V5AJmYC3AsbMIMytaK"

ALPINE_COMMANDS = [
    "ip link set eth0 up",
    "ip addr add 10.0.10.2/24 dev eth0",
    "ip route add default via 10.0.10.1",
    "echo nameserver 8.8.8.8 > /etc/resolv.conf",
    "nginx",
]


def gns3_request(path):
    url = f"{GNS3_URL}{path}"
    creds = base64.b64encode(f"{GNS3_USER}:{GNS3_PASS}".encode()).decode()
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def get_alpine_port():
    try:
        projects = gns3_request("/projects")
        opened = next((p for p in projects if p["status"] == "opened"), None)
        if not opened:
            return None
        nodes = gns3_request(f"/projects/{opened['project_id']}/nodes")
        webserver = next((n for n in nodes if n["name"] == "WebServer"), None)
        return webserver["console"] if webserver else None
    except Exception:
        return None


def wait_for_port(port, host="localhost", timeout=600):
    print(f"Alpine konsol bekleniyor (localhost:{port})...", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=2):
                print(" hazır.")
                return True
        except (ConnectionRefusedError, OSError):
            print(".", end="", flush=True)
            time.sleep(3)
    print(" ZAMAN AŞIMI!")
    return False


def configure_alpine():
    port = get_alpine_port()
    if port:
        print(f"Alpine console port: {port}")
    else:
        port = 5017
        print(f"GNS3 API'den port alınamadı, varsayılan kullanılıyor: {port}")

    if not wait_for_port(port):
        print("HATA: Alpine konsol açılmadı.")
        sys.exit(1)

    print("Alpine boot tamamlanıyor (10s)...")
    time.sleep(10)

    print("Alpine yapılandırılıyor...")
    child = pexpect.spawn(f"telnet localhost {port}", timeout=30)
    child.setecho(False)

    # Login veya doğrudan prompt bekle
    idx = child.expect(["#", "login:", "Password:", pexpect.TIMEOUT], timeout=20)
    if idx == 1:
        child.sendline("root")
        idx = child.expect(["#", "Password:", pexpect.TIMEOUT], timeout=10)
    if idx == 2:
        child.sendline("")
        child.expect("#", timeout=10)

    # Komutları tek tek çalıştır
    for cmd in ALPINE_COMMANDS:
        print(f"  -> {cmd}")
        child.sendline(cmd)
        child.expect(["#", pexpect.TIMEOUT], timeout=10)

    child.sendline("exit")
    child.close()

    print("Alpine hazır: 10.0.10.2 — nginx çalışıyor.")


if __name__ == "__main__":
    print("=== NetGuard Lab Başlatıcı ===")
    configure_alpine()
    print("Lab hazır.")
