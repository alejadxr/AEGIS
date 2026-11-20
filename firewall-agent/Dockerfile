# AEGIS firewall agent, all-in-one edition.
#
# Runs next to the AEGIS API in the Compose stack and enforces its blocks in
# the HOST's firewall. That needs the host network namespace and NET_ADMIN,
# which docker-compose.yml grants to this service and to nothing else.
# On a separate gateway (a Raspberry Pi, say) run main.py under systemd
# instead; see aegis-firewall.service.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables conntrack procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/aegis-firewall
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py dos_netshield.py docker-entrypoint.sh ./
RUN chmod 0755 docker-entrypoint.sh && mkdir -p /etc/aegis

# Root on purpose: this process exists to write iptables rules. It is the only
# privileged service in the stack, and every mutating route requires
# AEGIS_FIREWALL_SECRET.
ENV PYTHONUNBUFFERED=1 AEGIS_FIREWALL_PORT=8765
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import os,urllib.request;urllib.request.urlopen('http://%s:%s/health'%(os.environ.get('AEGIS_FIREWALL_BIND','127.0.0.1'),os.environ['AEGIS_FIREWALL_PORT']),timeout=4)"

ENTRYPOINT ["./docker-entrypoint.sh"]
