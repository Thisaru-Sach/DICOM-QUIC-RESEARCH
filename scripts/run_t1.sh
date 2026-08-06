#!/usr/bin/env bash
# run_t1.sh — T1 TCP/TLS baseline experiment
# Run on SENDER VM (10.10.0.11)
# Receiver must be running: python3 receiver/tcp_receiver.py
#
# Usage: bash scripts/run_t1.sh [--loss 0|5|10|20] [--trials 30]
#
# Before each loss level, SSH to receiver and run:
#   sudo bash scripts/inject_loss.sh <loss_pct>

set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

LOSS=${LOSS:-0}
TRIALS=${TRIALS:-30}
DELAY=${DELAY:-2}

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --loss)   LOSS="$2";   shift 2 ;;
    --trials) TRIALS="$2"; shift 2 ;;
    --delay)  DELAY="$2";  shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

echo "═══════════════════════════════════════════════════"
echo " T1 TCP/TLS  |  loss=${LOSS}%  trials=${TRIALS}"
echo "═══════════════════════════════════════════════════"

for SIZE_CLASS in small medium large; do
  case $SIZE_CLASS in
    small)  FILE="data/dicom/small/ct_small.dcm"   ; TIMEOUT=60  ;;
    medium) FILE="data/dicom/medium/ct_medium.dcm" ; TIMEOUT=180 ;;
    large)  FILE="data/dicom/large/ct_large.dcm"   ; TIMEOUT=600 ;;
  esac

  echo ""
  echo "── ${SIZE_CLASS} (${FILE})  timeout=${TIMEOUT}s ──"

  for i in $(seq 1 "${TRIALS}"); do
    python3 sender/tcp_sender.py \
      --host 10.10.0.12 \
      --port 9000 \
      --file "${FILE}" \
      --size-class "${SIZE_CLASS}" \
      --trial "${i}" \
      --loss-level "${LOSS}" \
      --timeout "${TIMEOUT}" \
      --log-dir logs
    sleep "${DELAY}"
  done
done

echo ""
echo "[T1] Done — loss=${LOSS}%  trials=${TRIALS}"