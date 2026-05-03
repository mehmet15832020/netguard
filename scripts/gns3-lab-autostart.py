#!/usr/bin/env python3
"""GNS3 lab tam otomatik başlatıcı: proje aç → node'ları başlat → Alpine ayarla."""

import json
import sys
import time
import urllib.request
import urllib.error
import base64
import pexpect

GNS3_URL = "http://127.0.0.1:3080/v2"
GNS3_USER = "admin"
GNS3_PASS = "KLMwSeS0mklkToRm5EAWuhBgumnr0HHrD2ezvIVikaeDy3V5AJmYC3AsbMIMytaK"
PROJECT_NAME = "netguard-lab"

ALPINE_COMMANDS = [
    "ip link set eth0 up",
    "ip addr add 10.0.10.2/24 dev eth0",
    "ip route add default via 10.0.10.1",
    "echo nameserver 8.8.8.8 > /etc/resolv.conf",
    "nginx",
]


def gns3(method, path, data=None):
    url = f"{GNS3_URL}{path}"
    creds = base64.b64encode(f"{GNS3_USER}:{GNS3_PASS}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}", "Content-Type": "application/json"}
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as r:
        content = r.read()
        return json.loads(content) if content else {}


def ensure_gns3_server(timeout=300):
    import subprocess
    print("GNS3 server kontrol ediliyor...", end="", flush=True)
    try:
        gns3("GET", "/version")
        print(" zaten çalışıyor.")
        return True
    except Exception:
        print(" başlatılıyor...", end="", flush=True)
        subprocess.Popen(
            ["/usr/bin/gns3server"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    start = time.time()
    while time.time() - start < timeout:
        try:
            gns3("GET", "/version")
            print(" hazır.")
            return True
        except Exception:
            print(".", end="", flush=True)
            time.sleep(5)
    print(" ZAMAN AŞIMI!")
    return False


def open_project():
    projects = gns3("GET", "/projects")
    project = next((p for p in projects if p["name"] == PROJECT_NAME), None)
    if not project:
        print(f"HATA: '{PROJECT_NAME}' projesi bulunamadı!")
        sys.exit(1)

    pid = project["project_id"]
    if project["status"] != "opened":
        print(f"Proje açılıyor: {PROJECT_NAME}...")
        gns3("POST", f"/projects/{pid}/open", {})
        time.sleep(3)
    else:
        print(f"Proje zaten açık: {PROJECT_NAME}")

    return pid


def start_all_nodes(pid):
    nodes = gns3("GET", f"/projects/{pid}/nodes")
    stopped = [n for n in nodes if n["status"] != "started" and n["node_type"] not in ("cloud", "ethernet_switch")]
    if stopped:
        print(f"{len(stopped)} node başlatılıyor...")
        gns3("POST", f"/projects/{pid}/nodes/start", {})
    else:
        print("Tüm node'lar zaten çalışıyor.")


def wait_for_nodes(pid, timeout=180):
    print("Node'ların boot etmesi bekleniyor...", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        nodes = gns3("GET", f"/projects/{pid}/nodes")
        qemu_nodes = [n for n in nodes if n["node_type"] == "qemu"]
        if qemu_nodes and all(n["status"] == "started" for n in qemu_nodes):
            print(" hazır.")
            return True
        print(".", end="", flush=True)
        time.sleep(10)
    print(" ZAMAN AŞIMI!")
    return False


def get_alpine_port(pid):
    nodes = gns3("GET", f"/projects/{pid}/nodes")
    webserver = next((n for n in nodes if n["name"] == "WebServer"), None)
    return webserver["console"] if webserver else None


def configure_alpine(port):
    print(f"Alpine konsol bekleniyor (port {port})...", end="", flush=True)
    start = time.time()
    import socket
    while time.time() - start < 120:
        try:
            with socket.create_connection(("localhost", port), timeout=2):
                print(" hazır.")
                break
        except (ConnectionRefusedError, OSError):
            print(".", end="", flush=True)
            time.sleep(5)
    else:
        print(" ZAMAN AŞIMI!")
        return

    print("Alpine boot tamamlanıyor (15s)...")
    time.sleep(15)

    print("Alpine yapılandırılıyor...")
    child = pexpect.spawn(f"telnet localhost {port}", timeout=30)
    child.setecho(False)

    idx = child.expect(["#", "login:", "Password:", pexpect.TIMEOUT], timeout=20)
    if idx == 1:
        child.sendline("root")
        idx = child.expect(["#", "Password:", pexpect.TIMEOUT], timeout=10)
    if idx == 2:
        child.sendline("")
        child.expect("#", timeout=10)

    for cmd in ALPINE_COMMANDS:
        print(f"  -> {cmd}")
        child.sendline(cmd)
        child.expect(["#", pexpect.TIMEOUT], timeout=10)

    child.sendline("exit")
    child.close()
    print("Alpine hazır: 10.0.10.2 — nginx çalışıyor.")


def main():
    print("=== NetGuard Lab Otomatik Başlatıcı ===")

    if not ensure_gns3_server():
        sys.exit(1)

    pid = open_project()
    start_all_nodes(pid)
    wait_for_nodes(pid)

    alpine_port = get_alpine_port(pid)
    if alpine_port:
        configure_alpine(alpine_port)
    else:
        print("HATA: WebServer node'u bulunamadı!")

    print("Lab hazır!")


if __name__ == "__main__":
    main()
