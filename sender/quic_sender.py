#!/usr/bin/env python3
"""
quic_sender.py — QUIC sender (T2: QUIC only, T4: QUIC + Reed-Solomon)
Research: QUIC-Based Secure Tunneling with Erasure Coding for Resilient DICOM Transmission
Author: A.S.T.S. Seemon (AS2022366), University of Sri Jayewardenepura

Stream layout:
    Stream 0       — control: metadata frame out, ACK in
    Stream 4,8,12… — one stream per fragment (T4) or one stream for raw file (T2)

Usage:
    # T2 — QUIC only
    python quic_sender.py \\
        --host 10.10.0.12 --port 9001 \\
        --cert ../certs/sender.crt --key ../certs/sender.key --ca ../certs/ca.crt \\
        --file ../data/dicom/small/test.dcm --size-class small \\
        --trial 1 --trials 30 --loss-level 0 --tier 2

    # T4 — QUIC + RS(6,4)
    python quic_sender.py \\
        --host 10.10.0.12 --port 9001 \\
        --cert ../certs/sender.crt --key ../certs/sender.key --ca ../certs/ca.crt \\
        --file ../data/dicom/small/test.dcm --size-class small \\
        --trial 1 --trials 30 --loss-level 5 --tier 4 --rs-n 6 --rs-k 4
"""

import argparse
import asyncio
import hashlib
import logging
import struct
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived, QuicEvent

sys.path.insert(0, str(Path(__file__).parent))
from chunker import encode as rs_encode

# ── Constants ────────────────────────────────────────────────────────────────

DEFAULT_PORT    = 9001
SEND_BUF        = 1_048_576  # 1MB — fewer Python-level loop iterations for large files
META_FIXED_FMT  = ">4sHdIBBBBBQ"
META_FIXED_SIZE = struct.calcsize(META_FIXED_FMT)
MAGIC           = b"DCMT"
VERSION         = 0x0001
SIZE_CLASS_MAP  = {"small": 0, "medium": 1, "large": 2}
MSG_METADATA    = 0x01


# ── Logging setup ─────────────────────────────────────────────────────────────

def setup_logging(log_dir: str) -> Path:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file  = log_path / f"quic_sender_{timestamp}.log"

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


# ── Framing ───────────────────────────────────────────────────────────────────

def build_metadata_frame(
    t_send_start: float,
    trial_number: int,
    tier: int,
    loss_level: int,
    file_size_class: str,
    file_size_bytes: int,
    file_sha256: str,
    filename: str,
    rs_n: int,
    rs_k: int,
    n_streams: int,
) -> bytes:
    sha_bytes   = file_sha256.encode("ascii")
    fname_bytes = filename.encode("utf-8")

    fixed = struct.pack(
        META_FIXED_FMT,
        MAGIC, VERSION,
        t_send_start,
        trial_number,
        tier,
        loss_level,
        SIZE_CLASS_MAP[file_size_class],
        rs_n, rs_k,
        file_size_bytes,
    )
    return fixed + sha_bytes + struct.pack(">HH", len(fname_bytes), n_streams) + fname_bytes


# ── QUIC protocol ─────────────────────────────────────────────────────────────

class DicomSenderProtocol(QuicConnectionProtocol):

    def __init__(self, *args, ack_timeout: float = 60.0, **kwargs):
        super().__init__(*args, **kwargs)
        self._ack_event   = asyncio.Event()
        self._ack_payload = None
        self._ack_timeout = ack_timeout

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            if event.stream_id == 0 and event.data:
                self._ack_payload = event.data
                self._ack_event.set()

    async def send_dicom(
        self,
        file_path: Path,
        t_send_start: float,
        trial_number: int,
        tier: int,
        loss_level: int,
        size_class: str,
        rs_n: int,
        rs_k: int,
        scratch_dir: Path,
    ) -> dict:
        data        = file_path.read_bytes()
        file_sha256 = hashlib.sha256(data).hexdigest()
        file_size   = len(data)

        if tier == 4 and rs_n > 0 and rs_k > 0:
            frag_dir   = scratch_dir / f"trial{trial_number:03d}_frags"
            # Run CPU-bound RS encoding in a thread so the event loop keeps
            # servicing the QUIC connection (keepalives/timers) during
            # long encodes on large files — otherwise the connection
            # idle-times-out mid-encode before any data is sent.
            loop = asyncio.get_running_loop()
            frag_paths = await loop.run_in_executor(
                None, rs_encode, str(file_path), rs_n, rs_k, str(frag_dir)
            )
            fragments  = [Path(p).read_bytes() for p in sorted(frag_paths)]
            n_streams  = rs_n
            shutil.rmtree(frag_dir, ignore_errors=True)  # free disk immediately
        else:
            fragments = [data]
            n_streams = 1
            rs_n = rs_k = 0

        meta = build_metadata_frame(
            t_send_start, trial_number, tier, loss_level,
            size_class, file_size, file_sha256, file_path.name,
            rs_n, rs_k, n_streams,
        )
        self._quic.send_stream_data(
            0,
            bytes([MSG_METADATA]) + struct.pack(">I", len(meta)) + meta,
            end_stream=False,
        )
        self.transmit()

        t_data_start = time.time()
        await asyncio.gather(*[
            self._send_fragment((idx + 1) * 4, idx, frag)
            for idx, frag in enumerate(fragments)
        ])
        t_data_end = time.time()

        try:
            await asyncio.wait_for(self._ack_event.wait(), timeout=self._ack_timeout)
        except asyncio.TimeoutError:
            return {
                "ok": False, "error": "ACK timeout",
                "t_send_start": t_send_start, "t_data_start": t_data_start,
                "t_data_end": t_data_end, "t_ack": time.time(),
                "file_size_bytes": file_size, "file_sha256": file_sha256,
                "n_streams": n_streams, "rs_n": rs_n, "rs_k": rs_k,
            }

        t_ack  = time.time()
        ack_ok = self._ack_payload == b"\x01"

        return {
            "ok":              ack_ok,
            "t_send_start":    t_send_start,
            "t_data_start":    t_data_start,
            "t_data_end":      t_data_end,
            "t_ack":           t_ack,
            "file_size_bytes": file_size,
            "file_sha256":     file_sha256,
            "n_streams":       n_streams,
            "rs_n":            rs_n,
            "rs_k":            rs_k,
            "handshake_ms":    (t_data_start - t_send_start) * 1000,
            "transfer_ms":     (t_data_end   - t_data_start) * 1000,
            "e2e_ms":          (t_ack        - t_send_start) * 1000,
        }

    async def _send_fragment(self, stream_id: int, idx: int, data: bytes) -> None:
        payload = struct.pack(">IH", len(data), idx) + data
        offset  = 0
        total   = len(payload)
        chunks_since_yield = 0
        while offset < total:
            end           = min(offset + SEND_BUF, total)
            is_last       = (end == total)
            self._quic.send_stream_data(stream_id, payload[offset:end], end_stream=is_last)
            self.transmit()
            offset = end
            chunks_since_yield += 1
            if chunks_since_yield >= 4:
                # Yield to event loop periodically so transmit() actually
                # flushes to the wire instead of only queuing internally
                await asyncio.sleep(0)
                chunks_since_yield = 0


# ── Trial runner ──────────────────────────────────────────────────────────────

async def run_trial(args: argparse.Namespace, trial_number: int) -> bool:
    config = QuicConfiguration(is_client=True, alpn_protocols=["dicom-quic"])
    config.load_cert_chain(args.cert, args.key)
    config.load_verify_locations(args.ca)
    config.verify_mode = True
    config.max_data        = 1_200 * 1024 * 1024   # 1.2GB — headroom over 1GB file
    config.max_stream_data = 1_200 * 1024 * 1024
    config.idle_timeout    = 300.0  # allow headroom for large-file processing pauses

    scratch = Path(args.scratch)
    scratch.mkdir(parents=True, exist_ok=True)

    t_send_start = time.time()

    try:
        async with connect(
            args.host, args.port,
            configuration=config,
            create_protocol=lambda *a, **kw: DicomSenderProtocol(
                *a, ack_timeout=args.ack_timeout, **kw
            ),
        ) as protocol:
            result = await protocol.send_dicom(
                file_path    = Path(args.file),
                t_send_start = t_send_start,
                trial_number = trial_number,
                tier         = args.tier,
                loss_level   = args.loss_level,
                size_class   = args.size_class,
                rs_n         = args.rs_n,
                rs_k         = args.rs_k,
                scratch_dir  = scratch,
            )

        status = "OK" if result["ok"] else result.get("error", "FAIL")
        log(
            f"[TRIAL {trial_number:03d}] {status:14s} | "
            f"e2e={result.get('e2e_ms', -1):8.1f}ms  "
            f"handshake={result.get('handshake_ms', -1):6.1f}ms  "
            f"transfer={result.get('transfer_ms', -1):8.1f}ms  | "
            f"streams={result['n_streams']}  "
            f"{result['file_size_bytes']:>12,} B"
        )
        return result["ok"]

    except Exception as exc:
        log(f"[TRIAL {trial_number:03d}] ERROR — {exc}")
        return False


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="QUIC DICOM sender — T2/T4")

    ap.add_argument("--host",       default="10.10.0.12")
    ap.add_argument("--port",       type=int, default=DEFAULT_PORT)
    ap.add_argument("--cert",       default="certs/sender.crt")
    ap.add_argument("--key",        default="certs/sender.key")
    ap.add_argument("--ca",         default="certs/ca.crt")
    ap.add_argument("--file",       required=True)
    ap.add_argument("--size-class", required=True, dest="size_class",
                    choices=["small", "medium", "large"])
    ap.add_argument("--tier",       type=int, default=2, choices=[2, 3, 4])
    ap.add_argument("--trial",      type=int, default=1)
    ap.add_argument("--trials",     type=int, default=1)
    ap.add_argument("--loss-level", type=int, default=0,
                    choices=[0, 5, 10, 20], dest="loss_level")
    ap.add_argument("--rs-n",       type=int, default=0, dest="rs_n")
    ap.add_argument("--rs-k",       type=int, default=0, dest="rs_k")
    ap.add_argument("--scratch", default="data/scratch")
    ap.add_argument("--delay",       type=float, default=2.0)
    ap.add_argument("--ack-timeout", type=float, default=60.0, dest="ack_timeout")
    ap.add_argument("--log-dir",    default="logs", dest="log_dir")

    args = ap.parse_args()

    if args.tier == 4 and (args.rs_n == 0 or args.rs_k == 0):
        print("ERROR: --tier 4 requires --rs-n and --rs-k", file=sys.stderr)
        sys.exit(1)

    setup_logging(args.log_dir)
    log(f"[CONFIG] host={args.host}:{args.port}  tier=T{args.tier}  "
        f"file={args.file}  trials={args.trials}  "
        f"loss={args.loss_level}%  RS=({args.rs_n},{args.rs_k})")

    successes = 0
    for i in range(args.trials):
        ok = asyncio.run(run_trial(args, args.trial + i))
        if ok:
            successes += 1
        if i < args.trials - 1:
            time.sleep(args.delay)

    log(f"[DONE] {successes}/{args.trials} succeeded")
    sys.exit(0 if successes == args.trials else 1)


if __name__ == "__main__":
    main()