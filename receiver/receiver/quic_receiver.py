#!/usr/bin/env python3
"""
quic_receiver.py — QUIC receiver (T2: QUIC only, T4: QUIC + Reed-Solomon)
Research: QUIC-Based Secure Tunneling with Erasure Coding for Resilient DICOM Transmission
Author: A.S.T.S. Seemon (AS2022366), University of Sri Jayewardenepura

Stream layout:
    Stream 0       — control: receives metadata, sends ACK
    Stream 4,8,12… — one data stream per fragment

CSV output: ~/dicom-quic-research/results/raw/quic_results.csv

Usage:
    python quic_receiver.py \\
        --port 9001 \\
        --cert ../certs/receiver.crt --key ../certs/receiver.key --ca ../certs/ca.crt \\
        --out-dir ../data/scratch/ \\
        --csv ../results/raw/quic_results.csv
"""

import argparse
import asyncio
import csv
import datetime
import hashlib
import logging
import struct
import shutil
import sys
import time
from pathlib import Path

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, QuicEvent

sys.path.insert(0, str(Path(__file__).parent.parent / "sender"))
from chunker import decode as rs_decode

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_PORT    = 9001
META_FIXED_FMT  = ">4sHdIBBBBBQ"
META_FIXED_SIZE = struct.calcsize(META_FIXED_FMT)
SIZE_CLASS_RMAP = {0: "small", 1: "medium", 2: "large"}
MSG_METADATA    = 0x01

CSV_FIELDS = [
    "timestamp", "tier", "protocol", "loss_level", "file_size_class",
    "file_size_bytes", "rs_n", "rs_k", "trial_number",
    "latency_ms", "transfer_only_ms", "completion", "sha256_match",
    "streams_received", "streams_expected", "filename",
]

# Module-level logger — set up once in main(), used everywhere
logger = logging.getLogger("quic_receiver")


# ── Logging setup ─────────────────────────────────────────────────────────────

def setup_logging(log_dir: str) -> Path:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file  = log_path / f"quic_receiver_{timestamp}.txt"

    fmt = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    file_handler   = logging.FileHandler(log_file)
    stdout_handler = logging.StreamHandler(sys.stdout)
    file_handler.setFormatter(fmt)
    stdout_handler.setFormatter(fmt)

    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)
    logger.addHandler(stdout_handler)

    logger.info(f"[LOG] Writing to {log_file}")
    return log_file


# ── CSV helpers ───────────────────────────────────────────────────────────────

def ensure_csv(csv_path: Path) -> None:
    if not csv_path.exists():
        csv_path.parent.mkdir(parents=True, exist_ok=True)
        with csv_path.open("w", newline="") as f:
            csv.DictWriter(f, fieldnames=CSV_FIELDS).writeheader()
        logger.info(f"[CSV] Created {csv_path}")


def append_csv(csv_path: Path, row: dict) -> None:
    with csv_path.open("a", newline="") as f:
        csv.DictWriter(f, fieldnames=CSV_FIELDS).writerow(row)


# ── Metadata parsing ──────────────────────────────────────────────────────────

def parse_metadata(meta_bytes: bytes) -> dict:
    fixed = meta_bytes[:META_FIXED_SIZE]
    rest  = meta_bytes[META_FIXED_SIZE:]

    magic, version, t_send_start, trial_number, tier, loss_level, \
        size_class_id, rs_n, rs_k, file_size_bytes = struct.unpack(META_FIXED_FMT, fixed)

    if magic != b"DCMT":
        raise ValueError(f"Bad magic: {magic!r}")

    sha256_hex          = rest[:64].decode("ascii")
    fname_len, n_streams = struct.unpack(">HH", rest[64:68])
    filename            = rest[68:68 + fname_len].decode("utf-8")

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
        "n_streams":       n_streams,
        "filename":        filename,
    }


# ── Per-connection protocol ───────────────────────────────────────────────────

class DicomReceiverProtocol(QuicConnectionProtocol):

    def __init__(self, *args, out_dir: Path, csv_path: Path, **kwargs):
        super().__init__(*args, **kwargs)
        self._out_dir       = out_dir
        self._csv_path      = csv_path
        self._stream_bufs:  dict[int, bytearray] = {}
        self._fragments:    dict[int, bytes]      = {}
        self._meta:         dict | None           = None
        self._ctrl_buf:     bytearray             = bytearray()
        self._meta_parsed:  bool                  = False
        self._t_recv_first: float | None          = None
        self._streams_done: int                   = 0
        self._done:         bool                  = False

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            if event.stream_id == 0:
                self._handle_control(event.data, event.end_stream)
            else:
                self._handle_data_stream(event.stream_id, event.data, event.end_stream)

    def _handle_control(self, data: bytes, end_stream: bool) -> None:
        self._ctrl_buf.extend(data)
        if self._meta_parsed or len(self._ctrl_buf) < 5:
            return

        msg_type  = self._ctrl_buf[0]
        if msg_type != MSG_METADATA:
            logger.warning(f"[WARN] Unexpected control message type: {msg_type:#x}")
            return

        frame_len = struct.unpack(">I", self._ctrl_buf[1:5])[0]
        if len(self._ctrl_buf) < 5 + frame_len:
            return

        self._meta        = parse_metadata(bytes(self._ctrl_buf[5:5 + frame_len]))
        self._meta_parsed = True

        logger.info(
            f"[META] trial={self._meta['trial_number']}  "
            f"tier=T{self._meta['tier']}  "
            f"loss={self._meta['loss_level']}%  "
            f"size={self._meta['file_size_class']}  "
            f"streams={self._meta['n_streams']}  "
            f"RS=({self._meta['rs_n']},{self._meta['rs_k']})  "
            f"file={self._meta['filename']}  "
            f"bytes={self._meta['file_size_bytes']:,}"
        )

    def _handle_data_stream(self, stream_id: int, data: bytes, end_stream: bool) -> None:
        if self._t_recv_first is None:
            self._t_recv_first = time.time()

        if stream_id not in self._stream_bufs:
            self._stream_bufs[stream_id] = bytearray()
        self._stream_bufs[stream_id].extend(data)

        if not end_stream:
            return

        buf = bytes(self._stream_bufs[stream_id])
        if len(buf) < 6:
            logger.warning(f"[WARN] Stream {stream_id}: too short ({len(buf)} bytes)")
            return

        frag_data_len, frag_idx = struct.unpack(">IH", buf[:6])
        frag_payload = buf[6:]

        if len(frag_payload) != frag_data_len:
            logger.warning(
                f"[WARN] Stream {stream_id}: length mismatch "
                f"(expected {frag_data_len}, got {len(frag_payload)})"
            )
            return

        self._fragments[frag_idx] = frag_payload
        self._streams_done += 1

        n_expected = self._meta['n_streams'] if self._meta else '?'
        logger.info(
            f"[STREAM] id={stream_id}  frag_idx={frag_idx}  "
            f"size={frag_data_len:,}B  "
            f"({self._streams_done}/{n_expected})"
        )
        self._check_completion()

    def _check_completion(self) -> None:
        if self._done or not self._meta_parsed:
            return

        rs_k     = self._meta["rs_k"]
        required = rs_k if rs_k > 0 else self._meta["n_streams"]

        if len(self._fragments) < required:
            return

        self._done = True
        asyncio.ensure_future(self._finalize(self._meta, time.time()))

    async def _finalize(self, meta: dict, t_recv_end: float) -> None:
        rs_n  = meta["rs_n"]
        rs_k  = meta["rs_k"]
        trial = meta["trial_number"]

        try:
            if rs_k > 0:
                frag_dir = self._out_dir / f"trial{trial:03d}_quic_frags"
                frag_dir.mkdir(parents=True, exist_ok=True)
                for frag_idx, frag_bytes in self._fragments.items():
                    fname = f"{meta['filename']}.frag{frag_idx:03d}_of_{rs_n:03d}"
                    (frag_dir / fname).write_bytes(frag_bytes)
                out_file = self._out_dir / f"trial{trial:03d}_{meta['filename']}"
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(
                    None, rs_decode, str(frag_dir), str(out_file), rs_n, rs_k
                )
                file_data = out_file.read_bytes()
            else:
                file_data = self._fragments[0]
                out_file  = self._out_dir / f"trial{trial:03d}_{meta['filename']}"
                out_file.write_bytes(file_data)

            sha256_actual = hashlib.sha256(file_data).hexdigest()
            sha256_ok     = sha256_actual == meta["sha256_expected"]
            completion    = 1 if sha256_ok else 0

        except Exception as exc:
            logger.error(f"[ERROR] Reconstruction failed: {exc}")
            sha256_ok  = False
            completion = 0

        self._quic.send_stream_data(0, b"\x01" if sha256_ok else b"\x00", end_stream=True)
        self.transmit()

        t_first          = self._t_recv_first or t_recv_end
        latency_ms       = (t_recv_end - meta["t_send_start"]) * 1000
        transfer_only_ms = (t_recv_end - t_first) * 1000
        tier_str         = {2: "QUIC", 3: "QUIC_MASQUE", 4: "QUIC_MASQUE_RS"}.get(meta["tier"], "QUIC")
        status           = "OK" if sha256_ok else "INTEGRITY_FAIL"

        logger.info(
            f"[DONE] {status:14s} | "
            f"latency={latency_ms:8.1f}ms  "
            f"transfer_only={transfer_only_ms:8.1f}ms  | "
            f"frags={len(self._fragments)}/{meta['n_streams']}  "
            f"sha256={'match' if sha256_ok else 'MISMATCH'}"
        )

        row = {
            "timestamp":        datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "tier":             meta["tier"],
            "protocol":         tier_str,
            "loss_level":       meta["loss_level"],
            "file_size_class":  meta["file_size_class"],
            "file_size_bytes":  meta["file_size_bytes"],
            "rs_n":             meta["rs_n"],
            "rs_k":             meta["rs_k"],
            "trial_number":     trial,
            "latency_ms":       round(latency_ms, 3),
            "transfer_only_ms": round(transfer_only_ms, 3),
            "completion":       completion,
            "sha256_match":     int(sha256_ok),
            "streams_received": len(self._fragments),
            "streams_expected": meta["n_streams"],
            "filename":         meta["filename"],
        }
        append_csv(self._csv_path, row)
        logger.info(f"[CSV] Row appended — trial {trial}")

        # Free disk immediately — integrity already verified via sha256_match
        try:
            frag_dir = self._out_dir / f"trial{trial:03d}_quic_frags"
            if frag_dir.exists():
                shutil.rmtree(frag_dir, ignore_errors=True)
            out_file = self._out_dir / f"trial{trial:03d}_{meta['filename']}"
            if out_file.exists():
                out_file.unlink()
        except Exception as exc:
            logger.warning(f"[WARN] Scratch cleanup failed: {exc}")


# ── Server factory ────────────────────────────────────────────────────────────

def make_protocol_factory(out_dir: Path, csv_path: Path):
    def factory(*args, **kwargs):
        return DicomReceiverProtocol(*args, out_dir=out_dir, csv_path=csv_path, **kwargs)
    return factory


# ── Entry point ───────────────────────────────────────────────────────────────

async def amain(args: argparse.Namespace) -> None:
    out_dir  = Path(args.out_dir)
    csv_path = Path(args.csv)
    out_dir.mkdir(parents=True, exist_ok=True)
    ensure_csv(csv_path)

    config = QuicConfiguration(is_client=False, alpn_protocols=["dicom-quic"])
    config.load_cert_chain(args.cert, args.key)
    if Path(args.ca).exists():
        config.load_verify_locations(args.ca)
    config.max_data        = 1_200 * 1024 * 1024   # 1.2GB — headroom over 1GB file
    config.max_stream_data = 1_200 * 1024 * 1024
    config.idle_timeout    = 300.0  # allow headroom for large-file processing pauses

    logger.info(f"[SERVER] Listening on 0.0.0.0:{args.port}  (QUIC, T2/T4)")
    logger.info(f"[SERVER] CSV → {csv_path}")
    logger.info(f"[SERVER] Files → {out_dir}")
    logger.info(f"[SERVER] Ctrl+C to stop")

    await serve(
        "0.0.0.0", args.port,
        configuration=config,
        create_protocol=make_protocol_factory(out_dir, csv_path),
    )
    await asyncio.Future()


def main():
    ap = argparse.ArgumentParser(description="QUIC DICOM receiver — T2/T4")

    ap.add_argument("--port",    type=int, default=DEFAULT_PORT)
    ap.add_argument("--cert",    default="certs/receiver.crt")
    ap.add_argument("--key",     default="certs/receiver.key")
    ap.add_argument("--ca",      default="certs/ca.crt")
    ap.add_argument("--out-dir", default="data/scratch", dest="out_dir")
    ap.add_argument("--csv",     default="results/raw/quic_results.csv")
    ap.add_argument("--log-dir", default="logs", dest="log_dir")

    args = ap.parse_args()
    setup_logging(args.log_dir)

    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        logger.info("[SERVER] Stopped.")


if __name__ == "__main__":
    main()