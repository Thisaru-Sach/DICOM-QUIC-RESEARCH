#!/usr/bin/env bash
# run_t3.sh — T3 QUIC + MASQUE proxy experiment
# Run on SENDER VM (10.10.0.11)
# Receiver must be running: python3 receiver/quic_receiver.py --port 4433 \
#   --cert certs/receiver.crt --key certs/receiver.key --ca certs/ca.crt
# Proxy is started/stopped automatically by this script.
#
# Usage: bash scripts/run_t3.sh [--loss 0|5|10|20] [--trials 30]

set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

LOSS=${LOSS:-0}
TRIALS=${TRIALS:-30}
DELAY=${DELAY:-2}
PROXY_PID=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --loss)   LOSS="$2";   shift 2 ;;
    --trials) TRIALS="$2"; shift 2 ;;
    --delay)  DELAY="$2";  shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

cleanup() {
  if [[ -n "${PROXY_PID}" ]]; then
    echo "[T3] Stopping proxy (PID ${PROXY_PID})"
    kill "${PROXY_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "═══════════════════════════════════════════════════"
echo " T3 QUIC+MASQUE  |  loss=${LOSS}%  trials=${TRIALS}"
echo "═══════════════════════════════════════════════════"

# Start proxy
echo "[T3] Starting MASQUE proxy on port 4435"
python3 proxy/masque_proxy.py \
  --listen-port 4435 \
  --remote-host 10.10.0.12 \
  --remote-port 4433 \
  --cert certs/proxy.crt \
  --key  certs/proxy.key \
  --ca   certs/ca.crt \
  --receiver-ca certs/ca.crt \
  --log-dir logs &
PROXY_PID=$!
sleep 2  # allow proxy to bind

echo "[T3] Proxy running (PID ${PROXY_PID})"

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
      --host 10.10.0.11 \
      --port 4435 \
      --file "${FILE}" \
      --size-class "${SIZE_CLASS}" \
      --tier 3 \
      --trial "${i}" \
      --loss-level "${LOSS}" \
      --ca certs/proxy.crt \
      --scratch data/scratch \
      --ack-timeout "${ACK_TIMEOUT}" \
      --log-dir logs
    sleep "${DELAY}"
  done
done

echo ""
echo "[T3] Done — loss=${LOSS}%  trials=${TRIALS}"