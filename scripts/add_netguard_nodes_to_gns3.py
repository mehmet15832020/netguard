"""
GNS3 netguard-lab projesine NetGuard Server ve Agent node'larını ekler.

Çalıştır: python3 scripts/add_netguard_nodes_to_gns3.py
"""

import json
import shutil
import uuid
from pathlib import Path

PROJECT_FILE = Path.home() / "GNS3/projects/733f4176-b1dc-4632-916a-a60228f2b316/netguard-lab.gns3"
BACKUP_FILE  = PROJECT_FILE.with_suffix(".gns3.bak")


def main():
    # Yedek al
    shutil.copy2(PROJECT_FILE, BACKUP_FILE)
    print(f"Yedek: {BACKUP_FILE}")

    with open(PROJECT_FILE) as f:
        data = json.load(f)

    nodes = data["topology"]["nodes"]
    links = data["topology"]["links"]

    existing_names = {n["name"] for n in nodes}
    if "NetGuard-Server" in existing_names:
        print("NetGuard-Server zaten mevcut, atlanıyor.")
        return

    # LAN-Switch bul
    lan_switch = next(n for n in nodes if n["name"] == "LAN-Switch")
    lan_sw_id  = lan_switch["node_id"]

    # Kullanılan LAN-Switch portlarını bul
    used_ports = set()
    for link in links:
        for ln in link.get("nodes", []):
            if ln["node_id"] == lan_sw_id:
                used_ports.add(ln["port_number"])
    next_port = max(used_ports) + 1 if used_ports else 4

    # Node UUID'leri
    server_id = str(uuid.uuid4())
    agent_id  = str(uuid.uuid4())

    # NetGuard Server node
    server_node = {
        "node_id":    server_id,
        "node_type":  "qemu",
        "name":       "NetGuard-Server",
        "console":    5010,
        "console_type": "vnc",
        "x": 200,
        "y": 100,
        "z": 1,
        "symbol": ":/symbols/qemu_guest.svg",
        "label": {"text": "NetGuard-Server", "x": -10, "y": -25},
        "properties": {
            "adapter_type":       "virtio-net-pci",
            "adapters":           2,
            "hda_disk_image":     "netguard-server.qcow2",
            "hda_disk_interface": "virtio",
            "kvm":                "require",
            "ram":                2048,
            "cpus":               2,
            "qemu_path":          "/usr/bin/qemu-system-x86_64",
        },
        "status": "stopped",
        "port_name_format": "eth{0}",
    }

    # NetGuard Agent node
    agent_node = {
        "node_id":    agent_id,
        "node_type":  "qemu",
        "name":       "NetGuard-Agent",
        "console":    5011,
        "console_type": "vnc",
        "x": 400,
        "y": 100,
        "z": 1,
        "symbol": ":/symbols/qemu_guest.svg",
        "label": {"text": "NetGuard-Agent", "x": -10, "y": -25},
        "properties": {
            "adapter_type":       "virtio-net-pci",
            "adapters":           1,
            "hda_disk_image":     "netguard-agent1.qcow2",
            "hda_disk_interface": "virtio",
            "kvm":                "require",
            "ram":                1024,
            "cpus":               1,
            "qemu_path":          "/usr/bin/qemu-system-x86_64",
        },
        "status": "stopped",
        "port_name_format": "eth{0}",
    }

    nodes.append(server_node)
    nodes.append(agent_node)

    # NetGuard-Server → LAN-Switch bağlantısı (port next_port)
    link_server = {
        "link_id":   str(uuid.uuid4()),
        "link_type": "ethernet",
        "nodes": [
            {"node_id": server_id, "port_number": 0, "adapter_number": 0, "label": {"text": "eth0"}},
            {"node_id": lan_sw_id, "port_number": next_port, "label": {"text": f"e{next_port}"}},
        ],
    }

    # NetGuard-Agent → LAN-Switch bağlantısı (port next_port+1)
    link_agent = {
        "link_id":   str(uuid.uuid4()),
        "link_type": "ethernet",
        "nodes": [
            {"node_id": agent_id, "port_number": 0, "adapter_number": 0, "label": {"text": "eth0"}},
            {"node_id": lan_sw_id, "port_number": next_port + 1, "label": {"text": f"e{next_port+1}"}},
        ],
    }

    links.append(link_server)
    links.append(link_agent)

    with open(PROJECT_FILE, "w") as f:
        json.dump(data, f, indent=4)

    print(f"✅ NetGuard-Server ve NetGuard-Agent eklendi")
    print(f"   LAN-Switch port {next_port} → NetGuard-Server eth0")
    print(f"   LAN-Switch port {next_port+1} → NetGuard-Agent eth0")
    print(f"   VNC konsol: Server=5010, Agent=5011")
    print(f"\nSonraki adım: GNS3'ü aç ve projeyi yükle")


if __name__ == "__main__":
    main()
