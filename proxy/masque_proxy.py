#!/usr/bin/env python3
"""
masque_proxy.py — QUIC tunnel proxy (T3: QUIC + MASQUE simulation)
Research: QUIC-Based Secure Tunneling with Erasure Coding for Resilient DICOM Transmission
Author: A.S.T.S. Seemon (AS2022366), University of Sri Jayewardenepura

Architecture:
    quic_sender.py  →  masque_proxy.py  →  quic_receiver.py
       port 4435        (this script)         port 4433
       inner QUIC        sender VM            receiver VM

Uses raw quic_event_received to preserve stream layout (stream 0 = control,
streams 4,8,12... = data fragments). Each inner stream is forwarded on the
same stream ID on the outer connection, preserving the protocol framing
expected by quic_receiver.py.

Usage (run on sender VM):
    python proxy/masque_proxy.py \
        --listen-port 4435 \
        --remote-host 10.10.0.12 \
        --remote-port 4433 \
        --cert certs/proxy.crt \
        --key  certs/proxy.key \
        --ca   certs/ca.crt \
        --receiver-ca certs/receiver.crt \
        --log-dir logs
"""

import argparse
import asyncio
import datetime
import logging
import sys
from pathlib import Path

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionTerminated

logger = logging.getLogger("masque_proxy")


# ── Logging ───────────────────────────────────────────────────────────────────

def setup_logging(log_dir: str) -> None:
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_path / f"masque_proxy_{ts}.txt"
    fmt      = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    for h in [logging.FileHandler(log_file), logging.StreamHandler(sys.stdout)]:
        h.setFormatter(fmt)
        logger.addHandler(h)
    logger.setLevel(logging.INFO)
    logger.info(f"[LOG] Writing to {log_file}")


# ── Outer tunnel (proxy → receiver) ──────────────────────────────────────────

class OuterTunnelProtocol(QuicConnectionProtocol):
    """Outbound QUIC connection to quic_receiver.py. Relays ACK back to inner."""

    def __init__(self, *args, inner_proto, **kwargs):
        super().__init__(*args, **kwargs)
        self._inner      = inner_proto
        self._stream_bufs: dict[int, bytearray] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            if sid not in self._stream_bufs:
                self._stream_bufs[sid] = bytearray()
            self._stream_bufs[sid].extend(event.data)
            if event.end_stream:
                data = bytes(self._stream_bufs.pop(sid))
                logger.info(f"[OUTER←] stream={sid}  {len(data)}B  (from receiver)")
                # Relay ACK back to sender on the same stream ID
                try:
                    self._inner._quic.send_stream_data(sid, data, end_stream=True)
                    self._inner.transmit()
                    logger.info(f"[INNER→] stream={sid}  {len(data)}B  (ACK to sender)")
                except Exception as exc:
                    logger.warning(f"[WARN] ACK relay failed: {exc}")

        elif isinstance(event, ConnectionTerminated):
            logger.info(f"[OUTER] Disconnected — {event.reason_phrase}")


# ── Inner tunnel (sender → proxy) ────────────────────────────────────────────

class InnerTunnelProtocol(QuicConnectionProtocol):
    """Inbound QUIC connection from quic_sender.py. Forwards streams to outer."""

    def __init__(self, *args, remote_host: str, remote_port: int,
                 outer_config: QuicConfiguration, **kwargs):
        super().__init__(*args, **kwargs)
        self._remote_host   = remote_host
        self._remote_port   = remote_port
        self._outer_config  = outer_config
        self._stream_bufs:  dict[int, bytearray] = {}
        self._outer:        OuterTunnelProtocol | None = None
        self._pending:      list[tuple[int, bytes, bool]] = []
        self._connecting:   bool = False

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            if sid not in self._stream_bufs:
                self._stream_bufs[sid] = bytearray()
            self._stream_bufs[sid].extend(event.data)

            if event.end_stream:
                data = bytes(self._stream_bufs.pop(sid))
                label = "control" if sid == 0 else f"frag stream"
                logger.info(f"[INNER←] stream={sid}  {len(data)}B  ({label})")
                self._enqueue(sid, data, end_stream=True)
            # For stream 0, also forward partial data as it arrives
            # so receiver gets metadata before fragment streams arrive
            elif sid == 0:
                data = bytes(self._stream_bufs[sid])
                self._stream_bufs[sid] = bytearray()
                self._enqueue(sid, data, end_stream=False)

        elif isinstance(event, ConnectionTerminated):
            logger.info(f"[INNER] Sender disconnected — {event.reason_phrase}")

    def _enqueue(self, stream_id: int, data: bytes, end_stream: bool) -> None:
        self._pending.append((stream_id, data, end_stream))
        if self._outer is not None:
            self._flush_pending()
        elif not self._connecting:
            self._connecting = True
            asyncio.ensure_future(self._open_outer_tunnel())

    def _flush_pending(self) -> None:
        if self._outer is None:
            return
        for (sid, data, end) in self._pending:
            try:
                self._outer._quic.send_stream_data(sid, data, end_stream=end)
                self._outer.transmit()
                logger.info(f"[OUTER→] stream={sid}  {len(data)}B  end={end}")
            except Exception as exc:
                logger.warning(f"[WARN] Forward failed stream={sid}: {exc}")
        self._pending.clear()

    async def _open_outer_tunnel(self) -> None:
        logger.info(f"[PROXY] Opening outer tunnel → {self._remote_host}:{self._remote_port}")
        try:
            async with connect(
                self._remote_host, self._remote_port,
                configuration=self._outer_config,
                create_protocol=lambda *a, **kw: OuterTunnelProtocol(
                    *a, inner_proto=self, **kw
                ),
            ) as outer:
                self._outer = outer
                logger.info("[PROXY] Outer tunnel established")
                self._flush_pending()
                await asyncio.sleep(300)
        except Exception as exc:
            logger.error(f"[PROXY] Outer tunnel failed: {exc}")
            self._connecting = False
            self._outer      = None


# ── Server factory ────────────────────────────────────────────────────────────

def make_inner_factory(remote_host: str, remote_port: int,
                       outer_config: QuicConfiguration):
    def factory(*args, **kwargs):
        return InnerTunnelProtocol(
            *args,
            remote_host=remote_host,
            remote_port=remote_port,
            outer_config=outer_config,
            **kwargs,
        )
    return factory


# ── Entry point ───────────────────────────────────────────────────────────────

async def amain(args: argparse.Namespace) -> None:
    outer_config = QuicConfiguration(is_client=True, alpn_protocols=["dicom-quic"])
    outer_config.max_data        = 1_200 * 1024 * 1024
    outer_config.max_stream_data = 1_200 * 1024 * 1024
    outer_config.idle_timeout    = 300.0
    outer_config.load_verify_locations(args.receiver_ca)

    inner_config = QuicConfiguration(is_client=False, alpn_protocols=["dicom-quic"])
    inner_config.load_cert_chain(args.cert, args.key)
    inner_config.max_data        = 1_200 * 1024 * 1024
    inner_config.max_stream_data = 1_200 * 1024 * 1024
    inner_config.idle_timeout    = 300.0
    if Path(args.ca).exists():
        inner_config.load_verify_locations(args.ca)

    logger.info(f"[PROXY] Inner listener  → 0.0.0.0:{args.listen_port}")
    logger.info(f"[PROXY] Outer target    → {args.remote_host}:{args.remote_port}")
    logger.info(f"[PROXY] ALPN            → dicom-quic")
    logger.info(f"[PROXY] Ctrl+C to stop")

    await serve(
        "0.0.0.0", args.listen_port,
        configuration=inner_config,
        create_protocol=make_inner_factory(
            args.remote_host, args.remote_port, outer_config
        ),
    )
    await asyncio.Future()


def main():
    ap = argparse.ArgumentParser(description="MASQUE tunnel proxy — T3")
    ap.add_argument("--listen-port",  type=int, default=4435,         dest="listen_port")
    ap.add_argument("--remote-host",  default="10.10.0.12",           dest="remote_host")
    ap.add_argument("--remote-port",  type=int, default=4433,         dest="remote_port")
    ap.add_argument("--cert",         default="certs/proxy.crt")
    ap.add_argument("--key",          default="certs/proxy.key")
    ap.add_argument("--ca",           default="certs/ca.crt")
    ap.add_argument("--receiver-ca",  default="certs/receiver.crt",   dest="receiver_ca")
    ap.add_argument("--log-dir",      default="logs",                 dest="log_dir")
    args = ap.parse_args()
    setup_logging(args.log_dir)

    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        logger.info("[PROXY] Stopped.")


if __name__ == "__main__":
    main()