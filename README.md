# DICOM-QUIC Research

Undergraduate thesis project evaluating QUIC-based secure tunneling with erasure coding for DICOM (medical imaging) transmission under simulated network degradation.

Full title: *Evaluating QUIC-Based Secure Tunneling with Erasure Coding for Resilient DICOM Transmission Under Simulated Correlated Network Degradation Conditions*

B.Sc. (Special) Computer Science, University of Sri Jayewardenepura. Supervised by Dr. Ravimal Bandara.

## What this is about

Hospitals move large DICOM files (CT/MRI scans) over networks that aren't always reliable — packet loss, jitter, correlated bursts of drops. TCP handles this okay but not great, especially over lossy links where a single dropped segment stalls the whole connection (head-of-line blocking). QUIC is supposed to fix some of that since it's built on UDP and doesn't have the same blocking behavior.

This project tests whether QUIC actually delivers on that, and whether adding forward error correction (Reed-Solomon) on top makes it meaningfully more resilient, using DICOM transfer as the real-world workload.

## The four tiers

| Tier | What it is |
|------|-----------|
| T1 | Plain TCP/TLS — baseline |
| T2 | QUIC via aioquic |
| T3 | QUIC + MASQUE (proxied) |
| T4 | QUIC + MASQUE + Reed-Solomon RS(6,4) erasure coding |

Each tier gets run under the same set of simulated loss conditions and file sizes, and results get compared statistically.

There's also a stretch-goal T5 (in-kernel QUIC via lxin/quic, throughput-only microbenchmark) and a planned T2b (Python userspace TCP/TLS, to fill out a 2x2 kernel/userspace × TCP/QUIC comparison) - not core to the main results but useful for context.

## Setup

Two VMs (Linux Mint, VirtualBox), same network:

- **Sender** — `10.10.0.11`
- **Receiver** — `10.10.0.12`

Sender initiates transfers, receiver logs and verifies. Network degradation (loss, correlated bursts) is injected on the sender side via `tc`/`netem`.

## Repo layout

```
sender/       sending-side implementation (TCP, QUIC, chunking, RS encoding)
receiver/     receiving-side implementation, synced over from the receiver VM
proxy/        MASQUE proxy
scripts/      run scripts per tier (run_t1.sh ... run_t4.sh), loss injection, run_all.sh
logs/         run logs (gitignored, not tracked)
data/         DICOM test files, all sizes (gitignored - too large for git)
results/      CSV output from test runs (gitignored)
certs/        TLS certs/keys (gitignored, never commit these)
```

`data/`, `logs/`, `results/`, and `certs/` are intentionally not in git. See `.gitignore`. The DICOM test files alone run from ~50MB to over 1GB depending on tier, so they stay local and get regenerated/re-sourced as needed rather than versioned.

## Syncing sender/receiver code

The receiver VM doesn't have its own git setup — the sender VM is the single place commits happen. Receiver-side code gets pulled over with rsync before each commit:

```bash
bash scripts/sync_receiver.sh
```

Then commit as usual from the sender VM.

## Running a test

```bash
bash scripts/run_t1.sh    # baseline
bash scripts/run_t4.sh    # full stack, QUIC+MASQUE+RS
```

Each run produces a CSV row per trial in `results/`, logged with timestamp, tier, protocol, loss level, file size class, latency, transfer time, and a SHA-256 match flag to confirm the file arrived intact.

## CSV schema

```
timestamp, tier, protocol, loss_level, file_size_class, file_size_bytes,
rs_n, rs_k, trial_number, latency_ms, transfer_only_ms, completion,
sha256_match, filename
```

## Stats

Analysis done in R (4.6.0): ART-ANOVA for the main effects, Cliff's delta for effect size, Mann-Whitney U pairwise with Holm-Bonferroni correction for multiple comparisons.

## Known issues / things fixed along the way

- aioquic stalls past ~1GB transfers - fixed with per-chunk `transmit()` calls and yielding via `asyncio.sleep(0)`.
- aioquic's `ACK_FRAME_CAPACITY` is hardcoded too low for sustained high-throughput transfer — patched to 1024.
- RS encoding was blocking the event loop - moved to `run_in_executor`.
- Default idle timeout was closing connections mid-transfer under loss - raised to 300s.
- At zero loss, aioquic is consistently slower than kernel TCP/TLS. This isn't a bug, it's expected - pure Python/userspace vs kernel-optimized TCP. Matches what Kosek et al. (2023) found too.

## Status

All four tiers implemented and validated (integrity checks + logging working end to end). Thesis draft is written (LaTeX, IEEE format) with results sections still placeholder pending the full experimental run across all loss conditions.

## Author

Thisaru Sachintha (A.S.T.S. Seemon)

# from sender VM
rsync -avz --progress \
  --exclude 'data/' --exclude 'logs/' --exclude 'certs/' \
  --exclude '.venv/' --exclude '__pycache__/' --exclude 'results/' \
  sender@10.10.0.12:~/dicom-quic-research/ ~/dicom-quic-research/receiver/