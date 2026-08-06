#!/usr/bin/env bash
# run_all.sh — Master experiment orchestration
# Run on SENDER VM (10.10.0.11)
#
# Prerequisites before running:
#   RECEIVER VM: python3 receiver/quic_receiver.py --port 4433 \
#                  --cert certs/receiver.crt --key certs/receiver.key --ca certs/ca.crt
#   RECEIVER VM: python3 receiver/tcp_receiver.py  (separate terminal)
#
# For each loss level block, SSH to receiver and run:
#   sudo bash scripts/inject_loss.sh <loss_pct>
#
# Full run (~30 trials × 3 sizes × 4 tiers × 4 loss levels × RS configs)
# Estimated time: 6–10 hours depending on file sizes and network.
#
# Usage:
#   bash scripts/run_all.sh                    # all tiers, all loss levels
#   bash scripts/run_all.sh --tier 2           # single tier
#   bash scripts/run_all.sh --loss 5           # single loss level
#   bash scripts/run_all.sh --trials 5 --dry   # quick smoke test

set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

TRIALS=30
DELAY=2
TIERS="1 2 3 4"
LOSS_LEVELS="0 5 10 20"
DRY=0

while [[ $# -gt 0 ]]; do
  case $1 in
    --trials) TRIALS="$2"; shift 2 ;;
    --delay)  DELAY="$2";  shift 2 ;;
    --tier)   TIERS="$2";  shift 2 ;;
    --loss)   LOSS_LEVELS="$2"; shift 2 ;;
    --dry)    DRY=1; TRIALS=2; shift ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

LOG_DIR="logs/run_all_$(date +%Y%m%d_%H%M%S)"
mkdir -p "${LOG_DIR}"

echo "═══════════════════════════════════════════════════════════"
echo " FULL EXPERIMENT RUN"
echo " Tiers      : ${TIERS}"
echo " Loss levels: ${LOSS_LEVELS}%"
echo " Trials     : ${TRIALS}"
echo " Log dir    : ${LOG_DIR}"
echo " Dry run    : ${DRY}"
echo "═══════════════════════════════════════════════════════════"
echo ""

for LOSS in ${LOSS_LEVELS}; do
  echo ""
  echo "████████████████████████████████████████████████"
  echo " LOSS LEVEL: ${LOSS}%"
  echo " → Run on receiver VM: sudo bash scripts/inject_loss.sh ${LOSS}"
  echo "████████████████████████████████████████████████"

  if [[ ${DRY} -eq 0 ]]; then
    echo " Waiting 10s for you to set loss on receiver VM..."
    sleep 10
  fi

  for TIER in ${TIERS}; do
    echo ""
    echo "── Tier ${TIER} | Loss ${LOSS}% ──"
    SCRIPT="scripts/run_t${TIER}.sh"

    if [[ ! -f "${SCRIPT}" ]]; then
      echo "[WARN] ${SCRIPT} not found, skipping"
      continue
    fi

    LOSS="${LOSS}" TRIALS="${TRIALS}" DELAY="${DELAY}" \
      bash "${SCRIPT}" 2>&1 | tee "${LOG_DIR}/t${TIER}_loss${LOSS}.log"

    echo "[run_all] Tier ${TIER} loss=${LOSS}% complete"
    sleep 3
  done
done

echo ""
echo "═══════════════════════════════════════════════════════════"
echo " ALL EXPERIMENTS COMPLETE"
echo " Results: results/raw/tcp_results.csv"
echo "          results/raw/quic_results.csv"
echo "═══════════════════════════════════════════════════════════"