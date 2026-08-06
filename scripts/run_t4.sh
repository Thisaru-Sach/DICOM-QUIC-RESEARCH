#!/usr/bin/env bash
# run_t4.sh — T4 QUIC + MASQUE + Reed-Solomon experiment
# Run on SENDER VM (10.10.0.11)
# Receiver must be running: python3 receiver/quic_receiver.py --port 4433 \
#   --cert certs/receiver.crt --key certs/receiver.key --ca certs/ca.crt
# Proxy is started/stopped automatically by this script.
#
# RS configs tested: RS(6,4) and RS(9,6)
# Usage: bash scripts/run_t4.sh [--loss 0|5|10|20] [--trials 30]

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
    echo "[T4] Stopping proxy (PID ${PROXY_PID})"
    kill "${PROXY_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

echo "═══════════════════════════════════════════════════"
echo " T4 QUIC+MASQUE+RS  |  loss=${LOSS}%  trials=${TRIALS}"
echo "═══════════════════════════════════════════════════"

# Start proxy
echo "[T4] Starting MASQUE proxy on port 4435"
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
sleep 2

echo "[T4] Proxy running (PID ${PROXY_PID})"

for RS_N_K in "6 4" "9 6"; do
  RS_N=$(echo $RS_N_K | cut -d' ' -f1)
  RS_K=$(echo $RS_N_K | cut -d' ' -f2)

  echo ""
  echo "══ RS(${RS_N},${RS_K}) ══"

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
        --tier 4 \
        --trial "${i}" \
        --loss-level "${LOSS}" \
        --rs-n "${RS_N}" \
        --rs-k "${RS_K}" \
        --ca certs/proxy.crt \
        --scratch data/scratch \
        --ack-timeout "${ACK_TIMEOUT}" \
        --log-dir logs
      sleep "${DELAY}"
    done
  done
done

echo ""
echo "[T4] Done — loss=${LOSS}%  trials=${TRIALS}"