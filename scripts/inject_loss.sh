#!/usr/bin/env bash
# inject_loss.sh — Apply or clear Gilbert-Elliott correlated loss via tc netem
# Run on RECEIVER VM (10.10.0.12) before each loss-level block.
#
# Usage:
#   sudo bash scripts/inject_loss.sh <loss_pct>   # 0 | 5 | 10 | 20
#   sudo bash scripts/inject_loss.sh clear
#
# Gilbert-Elliott model params (p=burst entry, r=burst exit):
#   5%  loss → p=0.10 r=0.50  (avg burst ~2 pkts)
#   10% loss → p=0.15 r=0.30  (avg burst ~3 pkts)
#   20% loss → p=0.25 r=0.20  (avg burst ~5 pkts)

IFACE="enp0s8"

case "${1}" in
  0|clear)
    tc qdisc del dev "${IFACE}" root 2>/dev/null && \
      echo "[NETEM] Cleared — no loss on ${IFACE}" || \
      echo "[NETEM] No rule to clear on ${IFACE}"
    ;;
  5)
    tc qdisc del dev "${IFACE}" root 2>/dev/null || true
    tc qdisc add dev "${IFACE}" root netem \
      loss gemodel 10% 50% 100% 0%
    echo "[NETEM] Loss=5%  Gilbert-Elliott p=10% r=50% on ${IFACE}"
    ;;
  10)
    tc qdisc del dev "${IFACE}" root 2>/dev/null || true
    tc qdisc add dev "${IFACE}" root netem \
      loss gemodel 15% 30% 100% 0%
    echo "[NETEM] Loss=10% Gilbert-Elliott p=15% r=30% on ${IFACE}"
    ;;
  20)
    tc qdisc del dev "${IFACE}" root 2>/dev/null || true
    tc qdisc add dev "${IFACE}" root netem \
      loss gemodel 25% 20% 100% 0%
    echo "[NETEM] Loss=20% Gilbert-Elliott p=25% r=20% on ${IFACE}"
    ;;
  *)
    echo "Usage: sudo bash inject_loss.sh <0|5|10|20|clear>"
    exit 1
    ;;
esac

# Verify
tc qdisc show dev "${IFACE}"