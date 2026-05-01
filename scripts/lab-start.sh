#!/usr/bin/env python3
"""
NetGuard Lab Başlatıcı
GNS3 açıldıktan sonra bu scripti çalıştır.
Alpine WebServer'ı otomatik olarak yapılandırır.
"""

import socket
import sys
import time
import pexpect

ALPINE_PORT = 5017
ALPINE_COMMANDS = [
    "ip link set eth0 up",
    "ip addr add 10.0.10.2/24 dev eth0",
    "ip route add default via 10.0.10.1",
    "echo nameserver 8.8.8.8 > /etc/resolv.conf",
    "nginx",
]


def wait_for_port(port, host="localhost", timeout=120):
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
    if not wait_for_port(ALPINE_PORT):
        print("HATA: Alpine konsol açılmadı.")
        sys.exit(1)

    print("Alpine boot tamamlanıyor (10s)...")
    time.sleep(10)

    print("Alpine yapılandırılıyor...")
    child = pexpect.spawn(f"telnet localhost {ALPINE_PORT}", timeout=30)
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
