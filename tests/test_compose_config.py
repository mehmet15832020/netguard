"""
O2 — Docker Compose yapısal doğrulama testleri.
Container başlatmadan YAML parse + dosya varlığı + env key kontrolü yapar.
"""

import os
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "docker-compose.yml"
ENV_EXAMPLE_PATH = ROOT / ".env.example"
BACKEND_DOCKERFILE = ROOT / "Dockerfile"
FRONTEND_DOCKERFILE = ROOT / "dashboard-v2" / "Dockerfile"
NGINX_DOCKERFILE = ROOT / "nginx" / "Dockerfile"


# ── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def compose() -> dict:
    with open(COMPOSE_PATH) as f:
        return yaml.safe_load(f)


@pytest.fixture(scope="module")
def env_keys() -> set:
    keys = set()
    with open(ENV_EXAMPLE_PATH) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                keys.add(line.split("=", 1)[0])
    return keys


# ── TestComposeStructure ──────────────────────────────────────────────────────

class TestComposeStructure:
    REQUIRED_SERVICES = {"backend", "frontend", "nginx", "postgres", "influxdb", "zeek"}

    def test_compose_file_is_valid_yaml(self):
        with open(COMPOSE_PATH) as f:
            data = yaml.safe_load(f)
        assert isinstance(data, dict)

    def test_compose_has_services_key(self, compose):
        assert "services" in compose

    def test_all_required_services_present(self, compose):
        missing = self.REQUIRED_SERVICES - set(compose["services"])
        assert not missing, f"Eksik servisler: {missing}"

    def test_compose_has_networks_key(self, compose):
        assert "networks" in compose

    def test_compose_has_volumes_key(self, compose):
        assert "volumes" in compose

    def test_required_volumes_declared(self, compose):
        required = {"netguard_data", "postgres_data", "influxdb_data", "zeek_logs", "ssl_certs"}
        declared = set(compose.get("volumes", {}) or {})
        missing = required - declared
        assert not missing, f"Eksik volume tanımları: {missing}"


# ── TestDockerfiles ───────────────────────────────────────────────────────────

class TestDockerfiles:
    def test_backend_dockerfile_exists(self):
        assert BACKEND_DOCKERFILE.is_file(), f"{BACKEND_DOCKERFILE} bulunamadı"

    def test_frontend_dockerfile_exists(self):
        assert FRONTEND_DOCKERFILE.is_file(), f"{FRONTEND_DOCKERFILE} bulunamadı"

    def test_nginx_dockerfile_exists(self):
        assert NGINX_DOCKERFILE.is_file(), f"{NGINX_DOCKERFILE} bulunamadı"

    def test_backend_build_context_is_root(self, compose):
        svc = compose["services"]["backend"]
        assert svc["build"]["context"] == "."

    def test_frontend_build_context(self, compose):
        svc = compose["services"]["frontend"]
        assert svc["build"]["context"] == "./dashboard-v2"

    def test_nginx_build_context(self, compose):
        svc = compose["services"]["nginx"]
        assert svc["build"]["context"] == "./nginx"


# ── TestHealthchecks ──────────────────────────────────────────────────────────

class TestHealthchecks:
    SERVICES_WITH_HEALTHCHECK = {"backend", "frontend", "postgres", "influxdb"}

    def test_all_critical_services_have_healthcheck(self, compose):
        for svc_name in self.SERVICES_WITH_HEALTHCHECK:
            svc = compose["services"][svc_name]
            assert "healthcheck" in svc, f"{svc_name} sağlık kontrolü yok"

    def test_healthcheck_has_required_fields(self, compose):
        required_fields = {"test", "interval", "timeout", "retries"}
        for svc_name in self.SERVICES_WITH_HEALTHCHECK:
            hc = compose["services"][svc_name]["healthcheck"]
            missing = required_fields - set(hc)
            assert not missing, f"{svc_name} sağlık kontrolünde eksik alanlar: {missing}"

    def test_postgres_healthcheck_uses_pg_isready(self, compose):
        hc = compose["services"]["postgres"]["healthcheck"]
        test_cmd = " ".join(hc["test"])
        assert "pg_isready" in test_cmd

    def test_backend_healthcheck_targets_health_endpoint(self, compose):
        hc = compose["services"]["backend"]["healthcheck"]
        test_cmd = " ".join(hc["test"])
        assert "/api/v1/health" in test_cmd

    def test_frontend_healthcheck_targets_port_3000(self, compose):
        hc = compose["services"]["frontend"]["healthcheck"]
        test_cmd = " ".join(hc["test"])
        assert "3000" in test_cmd


# ── TestDependencies ──────────────────────────────────────────────────────────

class TestDependencies:
    def test_backend_depends_on_postgres(self, compose):
        deps = compose["services"]["backend"].get("depends_on", {})
        assert "postgres" in deps

    def test_backend_postgres_condition_is_healthy(self, compose):
        deps = compose["services"]["backend"]["depends_on"]
        assert deps["postgres"]["condition"] == "service_healthy"

    def test_backend_influxdb_condition_is_started(self, compose):
        """InfluxDB isteğe bağlı — service_started (service_healthy değil)."""
        deps = compose["services"]["backend"]["depends_on"]
        assert "influxdb" in deps
        assert deps["influxdb"]["condition"] == "service_started"

    def test_frontend_depends_on_backend(self, compose):
        deps = compose["services"]["frontend"].get("depends_on", {})
        assert "backend" in deps
        assert deps["backend"]["condition"] == "service_healthy"

    def test_nginx_depends_on_backend_and_frontend(self, compose):
        deps = compose["services"]["nginx"].get("depends_on", {})
        assert "backend" in deps
        assert "frontend" in deps

    def test_nginx_waits_for_healthy_services(self, compose):
        deps = compose["services"]["nginx"]["depends_on"]
        assert deps["backend"]["condition"] == "service_healthy"
        assert deps["frontend"]["condition"] == "service_healthy"


# ── TestResourceLimits ────────────────────────────────────────────────────────

class TestResourceLimits:
    SERVICES_WITH_LIMITS = {"backend", "frontend", "nginx", "postgres", "influxdb"}

    def test_all_services_have_resource_limits(self, compose):
        for svc_name in self.SERVICES_WITH_LIMITS:
            svc = compose["services"][svc_name]
            deploy = svc.get("deploy", {})
            limits = deploy.get("resources", {}).get("limits", {})
            assert "cpus" in limits and "memory" in limits, \
                f"{svc_name} kaynak limiti tanımlanmamış (CIS Docker Benchmark §5.10)"

    def test_nginx_has_lowest_memory_limit(self, compose):
        def _mem_mb(svc_name):
            mem = compose["services"][svc_name]["deploy"]["resources"]["limits"]["memory"]
            mem = str(mem).upper()
            if mem.endswith("G"):
                return float(mem[:-1]) * 1024
            if mem.endswith("M"):
                return float(mem[:-1])
            return float(mem)

        nginx_mb = _mem_mb("nginx")
        backend_mb = _mem_mb("backend")
        assert nginx_mb < backend_mb, "nginx bellek limiti backend'den küçük olmalı"


# ── TestEnvExample ────────────────────────────────────────────────────────────

class TestEnvExample:
    REQUIRED_KEYS = {
        "JWT_SECRET_KEY",
        "POSTGRES_PASSWORD",
        "ADMIN_PASSWORD",
        "VIEWER_PASSWORD",
        "BREAK_GLASS_TOKEN",
        "INFLUXDB_TOKEN",
        "NETGUARD_HOST",
    }

    def test_env_example_file_exists(self):
        assert ENV_EXAMPLE_PATH.is_file()

    def test_required_keys_present(self, env_keys):
        missing = self.REQUIRED_KEYS - env_keys
        assert not missing, f".env.example'da eksik zorunlu key'ler: {missing}"

    def test_placeholder_keys_have_placeholder_values(self):
        placeholder_keys = {
            "JWT_SECRET_KEY",
            "POSTGRES_PASSWORD",
            "BREAK_GLASS_TOKEN",
        }
        with open(ENV_EXAMPLE_PATH) as f:
            content = f.read()
        for key in placeholder_keys:
            pattern = rf"^{re.escape(key)}=BURAYA_"
            assert re.search(pattern, content, re.MULTILINE), \
                f"{key} placeholder değeri bekleniyordu"

    def test_no_real_secrets_in_env_example(self):
        with open(ENV_EXAMPLE_PATH) as f:
            content = f.read()
        # Gerçek secret görünümlü değerler (hex/base64) — BURAYA_ placeholder'ları hariç
        suspicious_patterns = [
            r"JWT_SECRET_KEY=(?!BURAYA_)[a-f0-9]{32,}",
            r"POSTGRES_PASSWORD=(?!BURAYA_)[a-zA-Z0-9]{8,}",
            r"BREAK_GLASS_TOKEN=(?!BURAYA_)[a-f0-9]{32,}",
        ]
        for pattern in suspicious_patterns:
            assert not re.search(pattern, content), \
                f".env.example gerçek secret içeriyor: {pattern}"


# ── TestInstallScript ─────────────────────────────────────────────────────────

class TestInstallScript:
    INSTALL_SCRIPT = ROOT / "install.sh"

    def test_install_script_exists(self):
        assert self.INSTALL_SCRIPT.is_file(), "install.sh bulunamadı"

    def test_install_script_is_executable_or_has_shebang(self):
        with open(self.INSTALL_SCRIPT) as f:
            first_line = f.readline().strip()
        assert first_line.startswith("#!"), "install.sh shebang satırı yok"

    def test_install_script_references_compose_file(self):
        content = self.INSTALL_SCRIPT.read_text()
        assert "docker compose" in content or "docker-compose" in content

    def test_install_script_generates_secrets(self):
        content = self.INSTALL_SCRIPT.read_text()
        assert "openssl rand" in content

    def test_install_script_has_health_wait(self):
        content = self.INSTALL_SCRIPT.read_text()
        assert "healthy" in content

    def test_install_script_creates_credentials_file(self):
        content = self.INSTALL_SCRIPT.read_text()
        assert "credentials" in content.lower()

    def test_install_script_supports_host_argument(self):
        content = self.INSTALL_SCRIPT.read_text()
        assert "--host" in content


# ── TestZeekConfig ────────────────────────────────────────────────────────────

class TestZeekConfig:
    ZEEK_DIR = ROOT / "config" / "zeek"

    def test_zeek_local_zeek_exists(self):
        assert (self.ZEEK_DIR / "local.zeek").is_file()

    def test_zeek_start_sh_exists(self):
        assert (self.ZEEK_DIR / "start.sh").is_file()

    def test_zeek_service_uses_correct_volume_mounts(self, compose):
        svc = compose["services"]["zeek"]
        volumes = svc.get("volumes", [])
        volume_str = " ".join(str(v) for v in volumes)
        assert "local.zeek" in volume_str
        assert "start.sh" in volume_str

    def test_zeek_has_net_admin_capability(self, compose):
        svc = compose["services"]["zeek"]
        caps = svc.get("cap_add", [])
        assert "NET_ADMIN" in caps or "NET_RAW" in caps

    def test_zeek_configs_mounted_readonly(self, compose):
        svc = compose["services"]["zeek"]
        volumes = [str(v) for v in svc.get("volumes", [])]
        ro_volumes = [v for v in volumes if ":ro" in v]
        assert any("local.zeek" in v for v in ro_volumes), "local.zeek :ro mount edilmeli"
        assert any("start.sh" in v for v in ro_volumes), "start.sh :ro mount edilmeli"


# ── TestSecurityHardening ─────────────────────────────────────────────────────

class TestSecurityHardening:
    SERVICES_REQUIRING_NO_NEW_PRIVS = {"backend", "frontend", "nginx", "postgres", "influxdb", "zeek"}

    def test_all_services_have_no_new_privileges(self, compose):
        for svc_name in self.SERVICES_REQUIRING_NO_NEW_PRIVS:
            svc = compose["services"][svc_name]
            security_opts = svc.get("security_opt", [])
            has_nnp = any("no-new-privileges" in str(opt) for opt in security_opts)
            assert has_nnp, (
                f"{svc_name}: security_opt no-new-privileges:true eksik "
                f"(CIS Docker Benchmark v1.7 §5.25)"
            )

    def test_postgres_uses_timescaledb_image(self, compose):
        image = compose["services"]["postgres"].get("image", "")
        assert "timescale" in image, (
            f"postgres servisi TimescaleDB imajı kullanmalı, mevcut: {image}"
        )

    def test_postgres_image_includes_pg16(self, compose):
        image = compose["services"]["postgres"].get("image", "")
        assert "pg16" in image, f"postgres imajı pg16 içermeli, mevcut: {image}"

    def test_backend_healthcheck_checks_status_code(self, compose):
        hc = compose["services"]["backend"]["healthcheck"]
        test_cmd = " ".join(hc["test"])
        assert "sys.exit" in test_cmd or "exit" in test_cmd.lower(), \
            "backend healthcheck status code'u doğrulamalı"

    def test_influxdb_healthcheck_uses_http_ping(self, compose):
        hc = compose["services"]["influxdb"]["healthcheck"]
        test_cmd = " ".join(hc["test"])
        assert "/ping" in test_cmd or "ping" in test_cmd, \
            "influxdb healthcheck /ping endpoint kullanmalı"

    def test_backend_start_period_allows_migration(self, compose):
        hc = compose["services"]["backend"]["healthcheck"]
        start_period = hc.get("start_period", "0s")
        seconds = int(str(start_period).rstrip("s"))
        assert seconds >= 60, (
            f"backend start_period {start_period} — TimescaleDB migration için en az 60s gerekli"
        )
