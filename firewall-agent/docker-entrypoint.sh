#!/bin/sh
# Start the AEGIS firewall agent inside the Compose stack.
set -eu

# A rule written with the wrong iptables backend lands in tables the host
# never consults: the agent would report "blocked" while traffic flows. The
# image ships both backends; use the one the host's firewall already lives in
# (the one with more rules), the same heuristic Kubernetes' iptables-wrapper
# uses. AEGIS_IPTABLES overrides it.
if [ -z "${AEGIS_IPTABLES:-}" ]; then
  legacy=$( (iptables-legacy-save 2>/dev/null || true) | grep -c '^-' || true)
  nft=$( (iptables-nft-save 2>/dev/null || true) | grep -c '^-' || true)
  if [ "${legacy:-0}" -gt "${nft:-0}" ]; then
    AEGIS_IPTABLES=/usr/sbin/iptables-legacy
  else
    AEGIS_IPTABLES=/usr/sbin/iptables-nft
  fi
  export AEGIS_IPTABLES
  echo "aegis-firewall: host firewall backend is ${AEGIS_IPTABLES##*-} (legacy rules=${legacy:-0}, nft rules=${nft:-0})"
fi

if ! "$AEGIS_IPTABLES" -S INPUT >/dev/null 2>&1; then
  echo "aegis-firewall: cannot manage iptables with $AEGIS_IPTABLES." >&2
  echo "aegis-firewall: the service needs network_mode: host and cap_add NET_ADMIN (see docker-compose.yml)." >&2
  exit 1
fi

if [ -z "${AEGIS_FIREWALL_SECRET:-}" ]; then
  echo "aegis-firewall: AEGIS_FIREWALL_SECRET is not set; refusing to expose an unauthenticated firewall." >&2
  exit 1
fi

# Listen only where the API can reach it: the Compose network's gateway
# address on the host, never every interface of a machine on the internet.
exec python -m uvicorn main:app --host "${AEGIS_FIREWALL_BIND:-127.0.0.1}" --port "${AEGIS_FIREWALL_PORT:-8765}" --no-access-log
