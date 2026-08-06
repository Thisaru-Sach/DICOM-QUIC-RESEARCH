#!/usr/bin/env bash
# run_t2.sh — T2 QUIC-only experiment
# Run on SENDER VM (10.10.0.11)
# Receiver must be running: python3 receiver/quic_receiver.py --port 4433 \
#   --cert certs/receiver.crt --key certs/receiver.key --ca certs/ca.crt
#
# Usage: bash scripts/run_t2.sh [--loss 0|5|10|20] [--trials 30]

set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

LOSS=${LOSS:-0}
TRIALS=${TRIALS:-30}
DELAY=${DELAY:-2}

while [[ $# -gt 0 ]]; do
  case $1 in
    --loss)   LOSS="$2";   shift 2 ;;
    --trials) TRIALS="$2"; shift 2 ;;
    --delay)  DELAY="$2";  shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

echo "═══════════════════════════════════════════════════"
echo " T2 QUIC     |  loss=${LOSS}%  trials=${TRIALS}"
echo "═══════════════════════════════════════════════════"

for SIZE_CLASS in small medium large; do
  case $SIZE_CLASS in
    small)  FILE="data/dicom/small/ct_small.dcm"   ; ACK_TIMEOUT=60  ;;
    medium) FILE="data/dicom/medium/ct_medium.dcm" ; ACK_TIMEOUT=180 ;;
    large)  FILE="data/dicom/large/ct_large.dcm"   ; ACK_TIMEOUT=600 ;;
  esac

  echo ""
  echo "── ${SIZE_CLASS} (${FILE})  ack-timeout=${ACK_TIMEOUT}s ──"

  for i in $(seq 1 "${TRIALS}"); do
    python3 sender/quic_sender.py \
      --host 10.10.0.12 \
      --port 4433 \
      --file "${FILE}" \
      --size-class "${SIZE_CLASS}" \
      --tier 2 \
      --trial "${i}" \
      --loss-level "${LOSS}" \
      --ca certs/ca.crt \
      --scratch data/scratch \
      --ack-timeout "${ACK_TIMEOUT}" \
      --log-dir logs
    sleep "${DELAY}"
  done
done

echo ""
echo "[T2] Done — loss=${LOSS}%  trials=${TRIALS}"