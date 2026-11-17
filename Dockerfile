FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data
WORKDIR /srv

# nmap for the local (VPN sidecar) engine. cap_net_raw on the binary lets the
# non-root user run SYN/UDP scans (Docker grants NET_RAW to containers by default).
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap libcap2-bin \
 && setcap cap_net_raw+eip "$(command -v nmap)" \
 && apt-get purge -y libcap2-bin && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

RUN useradd -r -u 1000 sixy && mkdir -p /data && chown sixy /data
USER sixy
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/livez')" || exit 1
CMD ["waitress-serve", "--host=0.0.0.0", "--port=8080", "--threads=8", "--call", "app.main:create_app"]
