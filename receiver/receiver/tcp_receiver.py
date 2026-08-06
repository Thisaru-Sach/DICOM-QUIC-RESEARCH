#!/usr/bin/env python3
"""
tcp_receiver.py — TCP/TLS baseline receiver (T1 ablation tier)
Research: QUIC-Based Secure Tunneling with Erasure Coding for Resilient DICOM Transmission
Author: A.S.T.S. Seemon (AS2022366), University of Sri Jayewardenepura

Measurement model:
    latency_ms = t_recv_end - t_send_start
        t_send_start → embedded in metadata frame by sender (sender's clock)
        t_recv_end   → recorded by receiver after last byte written (receiver's clock)
    Both VMs sync to host clock via VBoxService — cross-clock delta valid to <1ms.

CSV output: ~/dicom-quic-research/results/raw/tcp_results.csv
Columns: timestamp, tier, protocol, loss_level, file_size_class, file_size_bytes,
         rs_n, rs_k, trial_number, latency_ms, transfer_only_ms, completion,
         sha256_match, filename

Usage:
    python tcp_receiver.py \\
        --port 9000 \\
        --cert ../certs/receiver.crt --key ../certs/receiver.key --ca ../certs/ca.crt \\
        --out-dir ../data/scratch/ \\
        --csv ../results/raw/tcp_results.csv
"""

import argparse
import csv
import datetime
import hashlib
import logging
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_PORT    = 9000
RECV_BUF        = 65536
META_FIXED_FMT  = ">4sHdIBBBBBQ"
META_FIXED_SIZE = struct.calcsize(META_FIXED_FMT)
SIZE_CLASS_RMAP = {0: "small", 1: "medium", 2: "large"}

CSV_FIELDS = [
    "timestamp", "tier", "protocol", "loss_level", "file_size_class",
    "file_size_bytes", "rs_n", "rs_k", "trial_number",
    "latency_ms", "transfer_only_ms", "completion", "sha256_match", "filename",
]


# ── Logging setup ─────────────────────────────────────────────────────────────

def setup_logging(log_dir: str) -> Path:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file  = log_path / f"tcp_receiver_{timestamp}.txt"

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


# ── Framing helpers ───────────────────────────────────────────────────────────

def recv_exactly(conn: ssl.SSLSocket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(min(RECV_BUF, n - len(buf)))
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def parse_metadata(meta_bytes: bytes) -> dict:
    fixed = meta_bytes[:META_FIXED_SIZE]
    rest  = meta_bytes[META_FIXED_SIZE:]

    magic, version, t_send_start, trial_number, tier, loss_level, \
        size_class_id, rs_n, rs_k, file_size_bytes = struct.unpack(META_FIXED_FMT, fixed)

    if magic != b"DCMT":
        raise ValueError(f"Bad magic: {magic!r}")

    sha256_hex = rest[:64].decode("ascii")
    fname_len  = struct.unpack(">H", rest[64:66])[0]
    filename   = rest[66:66 + fname_len].decode("utf-8")

    return {
        "t_send_start":    t_send_start,
        "trial_number":    trial_number,
        "tier":            tier,
        "loss_level":      loss_level,
        "file_size_class": SIZE_CLASS_RMAP.get(size_class_id, "unknown"),
        "rs_n":            rs_n,
        "rs_k":            rs_k,
        "file_size_bytes": file_size_bytes,
        "sha256_expected": sha256_hex,
        "filename":        filename,
    }


# ── CSV ───────────────────────────────────────────────────────────────────────

def ensure_csv(csv_path: Path) -> None:
    if not csv_path.exists():
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", newline="") as f:
            csv.DictWriter(f, fieldnames=CSV_FIELDS).writeheader()
        log(f"[CSV] Created {csv_path}")


def append_csv(csv_path: Path, row: dict) -> None:
    with csv_path.open("a", newline="") as f:
        csv.DictWriter(f, fieldnames=CSV_FIELDS).writerow(row)


# ── Connection handler ────────────────────────────────────────────────────────

def handle_connection(
    conn: ssl.SSLSocket,
    addr: tuple,
    out_dir: Path,
    csv_path: Path,
) -> None:
    log(f"[CONN] Accepted from {addr[0]}:{addr[1]}")

    try:
        meta_len  = struct.unpack(">I", recv_exactly(conn, 4))[0]
        meta      = parse_metadata(recv_exactly(conn, meta_len))

        log(
            f"[META] trial={meta['trial_number']}  tier=T{meta['tier']}  "
            f"loss={meta['loss_level']}%  size={meta['file_size_class']}  "
            f"file={meta['filename']}  bytes={meta['file_size_bytes']:,}"
        )

        data_len = struct.unpack(">Q", recv_exactly(conn, 8))[0]
        if data_len != meta["file_size_bytes"]:
            raise ValueError(
                f"Data length mismatch: header={meta['file_size_bytes']} frame={data_len}"
            )

        t_recv_first = time.time()
        file_data    = recv_exactly(conn, data_len)
        t_recv_end   = time.time()

        sha256_actual = hashlib.sha256(file_data).hexdigest()
        sha256_ok     = sha256_actual == meta["sha256_expected"]
        completion    = 1 if sha256_ok else 0

        conn.sendall(b"\x01" if sha256_ok else b"\x00")

        out_path = out_dir / f"trial{meta['trial_number']:03d}_{meta['filename']}"
        out_path.write_bytes(file_data)

        latency_ms       = (t_recv_end - meta["t_send_start"]) * 1000
        transfer_only_ms = (t_recv_end - t_recv_first) * 1000
        status           = "OK" if sha256_ok else "INTEGRITY_FAIL"

        log(
            f"[DONE] {status:14s} | "
            f"latency={latency_ms:8.1f}ms  "
            f"transfer_only={transfer_only_ms:8.1f}ms  | "
            f"sha256={'match' if sha256_ok else 'MISMATCH'}"
        )

        row = {
            "timestamp":        datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tier":             meta["tier"],
            "protocol":         "TCP_TLS",
            "loss_level":       meta["loss_level"],
            "file_size_class":  meta["file_size_class"],
            "file_size_bytes":  meta["file_size_bytes"],
            "rs_n":             meta["rs_n"],
            "rs_k":             meta["rs_k"],
            "trial_number":     meta["trial_number"],
            "latency_ms":       round(latency_ms, 3),
            "transfer_only_ms": round(transfer_only_ms, 3),
            "completion":       completion,
            "sha256_match":     int(sha256_ok),
            "filename":         meta["filename"],
        }
        append_csv(csv_path, row)
        log(f"[CSV] Row appended — trial {meta['trial_number']}")

    except (ConnectionError, ValueError, struct.error) as exc:
        log(f"[ERROR] {exc}")
        try:
            append_csv(csv_path, {
                "timestamp":        datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "tier":             1, "protocol": "TCP_TLS",
                "loss_level":       -1, "file_size_class": "unknown",
                "file_size_bytes":  0, "rs_n": 0, "rs_k": 0,
                "trial_number":     -1, "latency_ms": -1,
                "transfer_only_ms": -1, "completion": 0,
                "sha256_match":     0, "filename": "ERROR",
            })
        except Exception:
            pass
    finally:
        conn.close()


# ── Server loop ───────────────────────────────────────────────────────────────

def serve(args: argparse.Namespace) -> None:
    csv_path = Path(args.csv)
    out_dir  = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ensure_csv(csv_path)

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(args.cert, args.key)
    ssl_ctx.load_verify_locations(args.ca)
    ssl_ctx.verify_mode     = ssl.CERT_REQUIRED
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_srv:
        raw_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_srv.bind(("0.0.0.0", args.port))
        raw_srv.listen(1)

        log(f"[SERVER] Listening on 0.0.0.0:{args.port}  (TLS, T1 baseline)")
        log(f"[SERVER] CSV → {csv_path}")
        log(f"[SERVER] Files → {out_dir}")
        log(f"[SERVER] Ctrl+C to stop")

        with ssl_ctx.wrap_socket(raw_srv, server_side=True) as srv:
            while True:
                try:
                    conn, addr = srv.accept()
                    handle_connection(conn, addr, out_dir, csv_path)
                except KeyboardInterrupt:
                    log("[SERVER] Stopped.")
                    break
                except ssl.SSLError as exc:
                    log(f"[SSL ERROR] {exc} — waiting for next connection")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="TCP/TLS DICOM receiver — T1 baseline")

    ap.add_argument("--port",    type=int, default=DEFAULT_PORT)
    ap.add_argument("--cert",    default="certs/receiver.crt")
    ap.add_argument("--key",     default="certs/receiver.key")
    ap.add_argument("--ca",      default="certs/ca.crt")
    ap.add_argument("--out-dir", default="data/scratch", dest="out_dir")
    ap.add_argument("--csv",     default="results/raw/tcp_results.csv")
    ap.add_argument("--log-dir", default="logs", dest="log_dir")

    args = ap.parse_args()
    setup_logging(args.log_dir)
    serve(args)


if __name__ == "__main__":
    main()