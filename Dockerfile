FROM python:3.12-slim

WORKDIR /app

# tshark: pyshark paket yakalama için gerekli
RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tshark \
        snmp \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server/  ./server/
COPY shared/  ./shared/
COPY config/  ./config/

ENV NETGUARD_DB_PATH=/data/netguard.db \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000
EXPOSE 5140/udp
EXPOSE 2055/udp

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
