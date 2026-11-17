#!/usr/bin/env python3
"""
chunker.py — Reed-Solomon encode/decode module using zfec
Research: QUIC-Based Secure Tunneling with Erasure Coding for Resilient DICOM Transmission
Author: A.S.T.S. Seemon (AS2022366), University of Sri Jayewardenepura

Usage:
    # Encode
    python chunker.py encode <file> <n> <k> <output_dir>

    # Decode
    python chunker.py decode <fragment_dir> <output_file> <n> <k>

    # Self-test
    python chunker.py test
"""

import os
import sys
import time
import struct
import hashlib
import argparse
import glob
from pathlib import Path

import zfec


# Fragment filename convention: <stem>.frag<index>_of_<n>
FRAG_PATTERN = "{stem}.frag{idx:03d}_of_{n:03d}"
FRAG_GLOB    = "{stem}.frag*_of_{n:03d}"

# Block size used for streaming decode — bounds peak memory to
# O(DECODE_BLOCK_SIZE * k) instead of O(file_size * 3), which matters
# for large files (e.g. 1GB) where loading all fragments plus decoded
# output plus the joined result simultaneously risks OOM.
DECODE_BLOCK_SIZE = 4 * 1024 * 1024  # 4MB


def _pad_to_multiple(data: bytes, k: int) -> tuple[bytes, int]:
    """Pad data so len(data) is divisible by k. Returns (padded, original_len)."""
    original_len = len(data)
    remainder = original_len % k
    if remainder:
        data = data + b'\x00' * (k - remainder)
    return data, original_len


def encode(file_path: str, n: int, k: int, output_dir: str) -> list[str]:
    """
    Encode a file into n fragments, any k of which can reconstruct the original.

    Returns list of fragment file paths written.
    """
    file_path = Path(file_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not (1 <= k < n <= 256):
        raise ValueError(f"RS parameters must satisfy 1 <= k < n <= 256, got RS({n},{k})")

    print(f"[ENCODE] File     : {file_path} ({file_path.stat().st_size:,} bytes)")
    print(f"[ENCODE] RS config: RS({n},{k}) — any {k} of {n} fragments reconstruct")

    t0 = time.perf_counter()

    data = file_path.read_bytes()
    file_hash = hashlib.sha256(data).hexdigest()
    print(f"[ENCODE] SHA-256  : {file_hash}")

    padded, original_len = _pad_to_multiple(data, k)
    chunk_size = len(padded) // k
    print(f"[ENCODE] Chunk sz : {chunk_size:,} bytes × {k} data chunks + {n - k} parity")

    # Split into k equal chunks
    chunks = [padded[i * chunk_size:(i + 1) * chunk_size] for i in range(k)]

    # Encode with zfec — produces n blocks (k data + (n-k) parity)
    encoder = zfec.Encoder(k, n)
    fragments = encoder.encode(chunks)

    stem = file_path.name
    written = []

    for idx, frag in enumerate(fragments):
        frag_name = FRAG_PATTERN.format(stem=stem, idx=idx, n=n)
        frag_path = output_dir / frag_name

        # Header: magic(4) + n(1) + k(1) + index(1) + chunk_size(8) + original_len(8)
        header = struct.pack(">4sBBBQQ",
                             b"ZFEC",
                             n, k, idx,
                             chunk_size,
                             original_len)
        frag_path.write_bytes(header + frag)
        written.append(str(frag_path))

    elapsed = time.perf_counter() - t0
    frag_size = len(header) + chunk_size
    print(f"[ENCODE] Written  : {n} fragments × {frag_size:,} bytes → {output_dir}/")
    print(f"[ENCODE] Done in  : {elapsed * 1000:.1f} ms")

    return written


def decode(fragment_dir: str, output_file: str, n: int, k: int,
           stem: str = None, block_size: int = DECODE_BLOCK_SIZE) -> str:
    """
    Reconstruct original file from any k-of-n fragments found in fragment_dir.

    Streams the reconstruction in fixed-size blocks rather than loading
    entire fragments and the entire reconstructed file into memory at
    once. Peak memory stays roughly O(block_size * k) regardless of the
    original file size — critical for large files (hundreds of MB to
    several GB) where the naive whole-file approach risks OOM.

    stem: original filename (auto-detected if None).
    Returns output_file path.
    """
    fragment_dir = Path(fragment_dir)
    output_file  = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    HEADER_SIZE = struct.calcsize(">4sBBBQQ")

    # Find available fragments
    all_frags = sorted(fragment_dir.glob(f"*.frag*_of_{n:03d}"))
    if not all_frags:
        raise FileNotFoundError(f"No fragments matching *_of_{n:03d} in {fragment_dir}")

    # Pass 1: read only headers (cheap) to validate fragments and
    # determine chunk_size / original_len — do NOT read fragment bodies.
    frag_info: dict[int, tuple[Path, int, int]] = {}  # idx -> (path, chunk_size, original_len)

    for frag_path in all_frags:
        with open(frag_path, "rb") as f:
            header = f.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE:
            print(f"[DECODE] SKIP (too small): {frag_path.name}")
            continue
        magic, fn, fk, fidx, chunk_size, original_len = struct.unpack(">4sBBBQQ", header)
        if magic != b"ZFEC":
            print(f"[DECODE] SKIP (bad magic): {frag_path.name}")
            continue
        if fn != n or fk != k:
            print(f"[DECODE] SKIP (RS mismatch {fn},{fk}): {frag_path.name}")
            continue
        frag_info[fidx] = (frag_path, chunk_size, original_len)

    if len(frag_info) < k:
        raise RuntimeError(
            f"Need {k} fragments to reconstruct, only {len(frag_info)} valid fragments found"
        )

    # Pick exactly k fragments (prefer lower indices for determinism)
    selected_indices = sorted(frag_info.keys())[:k]
    _, chunk_size, original_len = frag_info[selected_indices[0]]

    print(f"[DECODE] Found    : {len(frag_info)} of {n} fragments")
    print(f"[DECODE] Using    : indices {selected_indices}")
    print(f"[DECODE] RS config: RS({n},{k}), chunk_size={chunk_size:,}, original={original_len:,} bytes")

    t0 = time.perf_counter()

    decoder = zfec.Decoder(k, n)

    # Open the k selected fragments, seek past their headers.
    handles = []
    try:
        for idx in selected_indices:
            frag_path, _, _ = frag_info[idx]
            fh = open(frag_path, "rb")
            fh.seek(HEADER_SIZE)
            handles.append(fh)

        # Pre-allocate the output file at full (padded) size so we can
        # seek-write each reconstructed chunk's blocks directly to its
        # correct offset without needing to hold the whole file.
        total_padded_size = chunk_size * k
        with open(output_file, "wb") as out:
            out.truncate(total_padded_size)

        # Stream-decode block by block.
        hasher = hashlib.sha256()  # NOTE: computed post-hoc below over final file
        with open(output_file, "r+b") as out:
            block_offset = 0
            while block_offset < chunk_size:
                this_block = min(block_size, chunk_size - block_offset)

                block_reads = [fh.read(this_block) for fh in handles]

                decoded_blocks = decoder.decode(block_reads, selected_indices)
                # decoded_blocks[i] corresponds to original data chunk i,
                # covering [block_offset : block_offset + this_block)
                # within that chunk. Write each to its correct absolute
                # offset in the output file.
                for i, db in enumerate(decoded_blocks):
                    out.seek(i * chunk_size + block_offset)
                    out.write(db)

                block_offset += this_block

        # Truncate off the zero-padding added at encode time.
        with open(output_file, "r+b") as out:
            out.truncate(original_len)

    finally:
        for fh in handles:
            fh.close()

    elapsed = time.perf_counter() - t0

    # Compute final SHA-256 by streaming the written file (avoids holding
    # the whole reconstructed file in memory just for hashing).
    hasher = hashlib.sha256()
    with open(output_file, "rb") as f:
        while True:
            chunk = f.read(block_size)
            if not chunk:
                break
            hasher.update(chunk)
    file_hash = hasher.hexdigest()

    print(f"[DECODE] SHA-256  : {file_hash}")
    print(f"[DECODE] Written  : {output_file} ({original_len:,} bytes)")
    print(f"[DECODE] Done in  : {elapsed * 1000:.1f} ms")

    return str(output_file)


def _self_test():
    """Encode a synthetic file, drop some fragments, decode, verify integrity."""
    import tempfile
    import random

    print("=" * 60)
    print("SELF-TEST: Reed-Solomon encode → drop fragments → decode")
    print("=" * 60)

    configs = [
        (6, 4),   # RS(6,4)
        (9, 6),   # RS(9,6)
        (10, 6),  # extra redundancy sanity check
    ]

    # Test with a few synthetic sizes
    test_sizes = [
        ("1 KB",   1_024),
        ("1 MB",   1_048_576),
        ("10 MB", 10_485_760),
    ]

    all_passed = True

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        for size_label, size_bytes in test_sizes:
            for n, k in configs:
                print(f"\n--- RS({n},{k}) | {size_label} ---")

                # Generate deterministic test data
                rng = random.Random(42)
                original = bytes(rng.getrandbits(8) for _ in range(size_bytes))
                original_hash = hashlib.sha256(original).hexdigest()

                src = tmp / f"test_{size_label.replace(' ','_')}.bin"
                src.write_bytes(original)

                frag_dir = tmp / f"frags_{n}_{k}_{size_label.replace(' ','_')}"
                frag_dir.mkdir()

                # Encode
                written = encode(str(src), n, k, str(frag_dir))

                # Drop (n-k) fragments — maximum allowable loss
                to_drop = n - k
                drop_indices = random.sample(range(n), to_drop)
                print(f"[TEST]  Dropping {to_drop} fragments: indices {sorted(drop_indices)}")
                for frag_path in written:
                    # Extract index from filename
                    fname = Path(frag_path).name
                    idx = int(fname.split(".frag")[1].split("_")[0])
                    if idx in drop_indices:
                        os.unlink(frag_path)
                        print(f"[TEST]  Deleted: {fname}")

                # Decode
                out_file = tmp / f"recovered_{n}_{k}_{size_label.replace(' ','_')}.bin"
                decode(str(frag_dir), str(out_file), n, k)

                # Verify
                recovered_hash = hashlib.sha256(out_file.read_bytes()).hexdigest()
                ok = recovered_hash == original_hash
                status = "PASS ✓" if ok else "FAIL ✗"
                print(f"[TEST]  Integrity: {status}")
                print(f"[TEST]  Original : {original_hash}")
                print(f"[TEST]  Recovered: {recovered_hash}")

                if not ok:
                    all_passed = False

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED ✓" if all_passed else "SOME TESTS FAILED ✗")
    print("=" * 60)
    return all_passed


def main():
    parser = argparse.ArgumentParser(
        description="Reed-Solomon chunker for DICOM research (zfec backend)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encode", help="Encode a file into RS fragments")
    enc.add_argument("file",       help="Input file path")
    enc.add_argument("n", type=int, help="Total fragments (e.g. 6)")
    enc.add_argument("k", type=int, help="Required fragments (e.g. 4)")
    enc.add_argument("output_dir", help="Directory to write fragments")

    dec = sub.add_parser("decode", help="Reconstruct file from RS fragments")
    dec.add_argument("fragment_dir", help="Directory containing fragments")
    dec.add_argument("output_file",  help="Path to write reconstructed file")
    dec.add_argument("n", type=int, help="Total fragments used at encode time")
    dec.add_argument("k", type=int, help="Required fragments")

    sub.add_parser("test", help="Run self-test with synthetic data")

    args = parser.parse_args()

    if args.cmd == "encode":
        encode(args.file, args.n, args.k, args.output_dir)
    elif args.cmd == "decode":
        decode(args.fragment_dir, args.output_file, args.n, args.k)
    elif args.cmd == "test":
        ok = _self_test()
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()