#!/usr/bin/env python3
"""
tcp_sender.py — TCP/TLS baseline sender (T1 ablation tier)
Research: QUIC-Based Secure Tunneling with Erasure Coding for Resilient DICOM Transmission
Author: A.S.T.S. Seemon (AS2022366), University of Sri Jayewardenepura

Protocol framing (all big-endian):
    [METADATA FRAME]
        4B  magic        "DCMT"
        2B  version      0x0001
        8B  t_send_start epoch float64 (sender wall clock, before connect)
        4B  trial_number
        1B  tier         1 = T1
        1B  loss_level   integer percent (0/5/10/20)
        1B  file_size_class  0=small 1=medium 2=large
        1B  rs_n         0 for T1
        1B  rs_k         0 for T1
        8B  file_size_bytes
        64B sha256       hex digest ASCII (no null terminator)
        2B  filename_len
        NB  filename     UTF-8

    [DATA FRAME]
        8B  data_length
        NB  raw file bytes

    [ACK — receiver → sender]
        1B  0x01 = integrity ok, 0x00 = integrity fail

Usage:
    python tcp_sender.py \\
        --host 10.10.0.12 --port 9000 \\
        --cert ../certs/sender.crt --key ../certs/sender.key --ca ../certs/ca.crt \\
        --file ../data/dicom/small/CT001.dcm --size-class small \\
        --trial 1 --trials 30 --loss-level 0
"""

import argparse
import hashlib
import logging
import socket
import ssl
import struct
import sys
import time
from datetime import datetime
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

MAGIC        = b"DCMT"
VERSION      = 0x0001
DEFAULT_PORT = 9000
SEND_BUF     = 65536
TIER         = 1

SIZE_CLASS_MAP = {"small": 0, "medium": 1, "large": 2}
META_FIXED_FMT  = ">4sHdIBBBBBQ"
META_FIXED_SIZE = struct.calcsize(META_FIXED_FMT)


# ── Logging setup ─────────────────────────────────────────────────────────────

def setup_logging(log_dir: str) -> Path:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file  = log_path / f"tcp_sender_{timestamp}.txt"

    fmt = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    file_handler   = logging.FileHandler(log_file)
    stdout_handler = logging.StreamHandler(sys.stdout)
    file_handler.setFormatter(fmt)
    stdout_handler.setFormatter(fmt)

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(stdout_handler)

    logging.info(f"[LOG] Writing to {log_file}")
    return log_file


def log(msg: str) -> None:
    logging.info(msg)


# ── Framing ──────────────────────────────────────────────────────────────────

def build_metadata_frame(
    t_send_start: float,
    trial_number: int,
    loss_level: int,
    file_size_class: str,
    file_size_bytes: int,
    file_sha256: str,
    filename: str,
) -> bytes:
    sha_bytes   = file_sha256.encode("ascii")
    fname_bytes = filename.encode("utf-8")

    fixed = struct.pack(
        META_FIXED_FMT,
        MAGIC, VERSION,
        t_send_start,
        trial_number,
        TIER,
        loss_level,
        SIZE_CLASS_MAP[file_size_class],
        0, 0,
        file_size_bytes,
    )
    return fixed + sha_bytes + struct.pack(">H", len(fname_bytes)) + fname_bytes


def send_all_chunked(conn: ssl.SSLSocket, data: bytes) -> None:
    offset = 0
    total  = len(data)
    while offset < total:
        end = min(offset + SEND_BUF, total)
        conn.sendall(data[offset:end])
        offset = end


# ── Trial ─────────────────────────────────────────────────────────────────────

def run_trial(args: argparse.Namespace, trial_number: int) -> bool:
    file_path   = Path(args.file)
    data        = file_path.read_bytes()
    file_sha256 = hashlib.sha256(data).hexdigest()
    file_size   = len(data)

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.load_verify_locations(args.ca)
    ssl_ctx.load_cert_chain(args.cert, args.key)
    ssl_ctx.verify_mode     = ssl.CERT_REQUIRED
    ssl_ctx.check_hostname  = False
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        raw_sock.settimeout(args.timeout)

        t_send_start = time.time()

        conn = ssl_ctx.wrap_socket(raw_sock, server_hostname=args.host)
        conn.connect((args.host, args.port))

        t_connected = time.time()

        meta = build_metadata_frame(
            t_send_start, trial_number, args.loss_level,
            args.size_class, file_size, file_sha256, file_path.name,
        )
        conn.sendall(struct.pack(">I", len(meta)) + meta)

        conn.sendall(struct.pack(">Q", file_size))
        t_data_start = time.time()
        send_all_chunked(conn, data)
        t_data_end = time.time()

        ack = conn.recv(1)
        t_ack = time.time()
        conn.close()

        ack_ok       = ack == b"\x01"
        handshake_ms = (t_connected  - t_send_start) * 1000
        transfer_ms  = (t_data_end   - t_data_start) * 1000
        e2e_ms       = (t_ack        - t_send_start) * 1000
        status       = "OK" if ack_ok else "INTEGRITY_FAIL"

        log(
            f"[TRIAL {trial_number:03d}] {status:14s} | "
            f"e2e={e2e_ms:8.1f}ms  "
            f"handshake={handshake_ms:6.1f}ms  "
            f"transfer={transfer_ms:8.1f}ms  | "
            f"{file_size:>12,} B  sha256={file_sha256[:16]}…"
        )
        return ack_ok

    except socket.timeout:
        log(f"[TRIAL {trial_number:03d}] TIMEOUT")
        return False
    except (socket.error, ssl.SSLError, ConnectionRefusedError) as exc:
        log(f"[TRIAL {trial_number:03d}] ERROR — {exc}")
        return False


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="TCP/TLS DICOM sender — T1 baseline")

    ap.add_argument("--host",       default="10.10.0.12")
    ap.add_argument("--port",       type=int, default=DEFAULT_PORT)
    ap.add_argument("--cert",       default="certs/sender.crt")
    ap.add_argument("--key",        default="certs/sender.key")
    ap.add_argument("--ca",         default="certs/ca.crt")
    ap.add_argument("--file",       required=True)
    ap.add_argument("--size-class", required=True, dest="size_class",
                    choices=["small", "medium", "large"])
    ap.add_argument("--trial",      type=int, default=1)
    ap.add_argument("--trials",     type=int, default=1)
    ap.add_argument("--loss-level", type=int, default=0,
                    choices=[0, 5, 10, 20], dest="loss_level")
    ap.add_argument("--delay",      type=float, default=2.0)
    ap.add_argument("--timeout",    type=float, default=120.0)
    ap.add_argument("--log-dir",    default="logs", dest="log_dir")

    args = ap.parse_args()
    setup_logging(args.log_dir)

    log(f"[CONFIG] host={args.host}:{args.port}  file={args.file}")
    log(f"[CONFIG] trials={args.trials}  loss={args.loss_level}%  size={args.size_class}")

    successes = 0
    for i in range(args.trials):
        ok = run_trial(args, args.trial + i)
        if ok:
            successes += 1
        if i < args.trials - 1:
            time.sleep(args.delay)

    log(f"[DONE] {successes}/{args.trials} succeeded")
    sys.exit(0 if successes == args.trials else 1)


if __name__ == "__main__":
    main()