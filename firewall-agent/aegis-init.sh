#!/bin/bash
# Idempotent AEGIS gateway init: AEGIS_BLOCK (dynamic IP blocks) + AEGIS_DOS
# (DoS/DDoS hardening). Re-runnable; flushes DoS chains before repopulating so
# reruns never duplicate. rp_filter stays 0 (multi-homed gateway).
set -e
IPT=/usr/sbin/iptables

# --- AEGIS_BLOCK (dynamic per-IP blocks, populated by aegis-firewall agent) ---
$IPT -L AEGIS_BLOCK -n >/dev/null 2>&1 || $IPT -N AEGIS_BLOCK
$IPT -C INPUT -j AEGIS_BLOCK 2>/dev/null || $IPT -I INPUT 1 -j AEGIS_BLOCK
$IPT -C FORWARD -j AEGIS_BLOCK 2>/dev/null || $IPT -I FORWARD 1 -j AEGIS_BLOCK

# --- AEGIS_DOS (INPUT: protect the Pi own services from floods) ---
$IPT -N AEGIS_DOS 2>/dev/null || $IPT -F AEGIS_DOS
$IPT -A AEGIS_DOS -i lo -j RETURN
$IPT -A AEGIS_DOS -i tailscale0 -j RETURN
$IPT -A AEGIS_DOS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
$IPT -A AEGIS_DOS -m conntrack --ctstate INVALID -j DROP
$IPT -A AEGIS_DOS -p icmp --icmp-type echo-request -m hashlimit --hashlimit-name aegis_icmp --hashlimit-mode srcip --hashlimit-above 10/sec --hashlimit-burst 30 -j DROP
$IPT -A AEGIS_DOS -p tcp --syn -m hashlimit --hashlimit-name aegis_syn --hashlimit-mode srcip --hashlimit-above 60/sec --hashlimit-burst 120 -j DROP
$IPT -A AEGIS_DOS -j RETURN
$IPT -C INPUT -j AEGIS_DOS 2>/dev/null || $IPT -A INPUT -j AEGIS_DOS

# --- AEGIS_DOS_FWD (FORWARD: drop only INVALID; never blocks legit forwarding) ---
$IPT -N AEGIS_DOS_FWD 2>/dev/null || $IPT -F AEGIS_DOS_FWD
$IPT -A AEGIS_DOS_FWD -m conntrack --ctstate INVALID -j DROP
$IPT -A AEGIS_DOS_FWD -j RETURN
$IPT -C FORWARD -j AEGIS_DOS_FWD 2>/dev/null || $IPT -A FORWARD -j AEGIS_DOS_FWD

echo "AEGIS_BLOCK + AEGIS_DOS chains initialized."

