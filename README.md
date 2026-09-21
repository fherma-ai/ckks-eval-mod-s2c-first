# CKKS EvalMod, S2C-first — a submission

A submission to the specification `eval-mod/s2c@1.0.0`: one call to Poulpy's
EvalMod — the homomorphic modular reduction that removes the integer parts a
ModUp introduced, by a polynomial approximation of the sine — on one of the
two halves CoeffsToSlots leaves, timed. It is the fourth and last stage of
Poulpy's S2C-first bootstrapping (`SlotsToCoeffs → ModUp → CoeffsToSlots →
EvalMod`), run on each half; at this point about a tenth of its time. Poulpy
0.8.3, toolchain `nightly-2026-05-14`.

This directory is the reference implementation, and the harness the platform
measures every submission in: `fherma.toml [harness]` says which files are
the specification's (pinned — laid over every submission's clone) and which
are the author's. The reference is the harness with `src/init.rs`, `run.rs`
and `free.rs` as they ship, built on the fastest backend Poulpy has
(`ifma-rayon`, every core). A submission that keeps them competes on backend
and threads; one that replaces `run.rs` competes on the algorithm and must
produce the same bytes.

## The stage's contract

The stage is exactly what `ckks_bootstrap` does last, on each half, and the
composition test in `../ckks-stages-check` is what says so: the stages
chained through this crate's code reproduce the one-shot bootstrap byte for
byte.

| | |
|---|---|
| Input | the real half CoeffsToSlots leaves: the case's message encrypted at the input layout, through the reference SlotsToCoeffs, ModUp and CoeffsToSlots, the guard bits taken off the scale — 1184 bits; slot `j` holds the real part of the message's slot `j` plus an integer multiple of the raised-from modulus. Made by `generate`, not measured |
| Operation | `ckks_eval_mod` on the preset's compiled EvalMod: the Han–Ki even cosine polynomial (degree 30, 16 intervals, coefficients at scale 2⁴², evaluated at scale 2⁵⁸) by baby-step/giant-step over a power basis, then three rounds of the double-angle formula, each a ct×ct squaring relinearised with the tensor key |
| Output | one ciphertext at 720 bits, back at scale 2³⁵, whose slot `j` holds the real part of the message's slot `j` — the integer parts removed |

The imaginary half is the same operation on the other half; the
bootstrapping runs both and adds `re + i·im`.

## Files

Three functions are yours; the envelope and the loop are the platform's:

| File | Owner | Role |
|---|---|---|
| `src/init.rs` | **you** | `init(&Point, &Context, config) → State`: your setup over the point and the context — the output buffers, a working arena, keys onto a GPU. Never sees a case. Not measured |
| `src/run.rs` | **you** | `run(&mut State, &Input) → &Output` — EvalMod into the output buffer. **The only thing timed** |
| `src/free.rs` | **you** | `free(State)`: your teardown. Not measured |
| `Cargo.toml` | **you** | the backend, as one cargo feature under `[features] default` |
| `config.jsonc` | **you** | `threads`, for a `*-rayon` backend; `0` is every core |
| `rust-toolchain.toml` | you | `nightly-2026-05-14`; Poulpy needs nightly |
| `src/envelope/mod.rs` | specification, pinned | the envelope: `setup` (keygen from `key_seed` — the same as the bootstrapping's), `generate` (the case, see *The contract*), `serialize` (the output as canonical bytes), `check` (the form of the output, and what it measures); `WARMUP` |
| `src/envelope/{keys,case,bytes,check,backend}.rs` | specification, pinned | the envelope's parts; `backend.rs` picks the Poulpy backend from the cargo feature |
| `src/fherma.rs` | generated, pinned | the types, from the signature: `Point {N, log_delta, output_k, key_seed}`, `Inputs {case_seed}`, `Outputs {ct}` |
| `src/main.rs` | generated, pinned | the loop: `setup → init → [generate → warm-up → run → serialize → check]* → free`; point directory in, `out/` and `results.json` out, the clock around `run`. `fherma-lang emit --solution --envelope <signature>` |

## What is measured

One call to `run` per case, wall-clock seconds, after three discarded warm-up
calls on the first case. Every other stage is timed and reported beside it,
and none of them is the score:

| In `out/results.json` | Seconds spent |
|---|---|
| `setup_s` | the envelope's keygen and compiled bootstrapping context, once |
| `init_s` | your `init`, once |
| `warmup_s` | the three warm-up calls, once |
| per case `generate_s` | the case from its seed: encode, encrypt, SlotsToCoeffs, ModUp, CoeffsToSlots |
| per case `seconds` | **the score**: one `run` |
| per case `digest_s`, `write_s` | serialising the output and writing it |
| per case `check_s` | decrypting it for its precision |
| per case `metrics.snr_bits` | signal-to-noise ratio in bits of the output's real slots against the message's real parts — scale-invariant, Poulpy's `snr_bits` (its `EVALMOD-PREC`) |
| per case `valid` | the output has the form the stage leaves: the input's ring, slots and sparsity, narrower than the input |
| `config` | your `config.jsonc`, as the run saw it |
| `max_rss_bytes` | the process's peak resident memory, bytes |

## How correctness is judged

By digest against the reference. The output ciphertext is serialised
canonically — `"fherma/ckks-ct/v1"`, then `n, cols, base2k, k, log_delta,
slots` as little-endian u64, then the limbs carrying the current `k` bits of
every column as little-endian i64 — and written as `out/NNNNNN/ct.bin`. The
platform takes its sha256 and compares it with the one the reference
produced for the same point and seed. Equal is a pass; there is no tolerance.

## The point and the case

| | |
|---|---|
| Point | `{N, log_delta, output_k, key_seed}` — the same point as `ckks-bootstrapping/s2c`: it names the preset (`n16_d35_k720_p19_s2c`), and the stage's widths follow from it. Today one: `N=65536, log_delta=35, output_k=720, key_seed=0` |
| Case | one seed. `cases/NNNNNN/case_seed.bin` holds it as a u64, little-endian; that is the whole input. The stage's input is made from it here, because making it needs the secret |
| Keys | from the point's `key_seed`: the same keys for everybody at a point, and the same keys as the bootstrapping's |

Every random stream is `sha256("fherma/ckks-bootstrap/" ‖ seed ‖ "/" ‖ name)`,
as in the bootstrapping harness: `sk`, `xs`, `xe`, `xa` from `key_seed`;
`msg`, `input-xa`, `input-xe` from the case seed. The message is `N/2` points
uniform on the unit disc, drawn with multiplication and comparison only — no
libm — so it is the same vector bit-for-bit on every platform. The fresh
ciphertext of a seed here is byte for byte the bootstrapping's input for that
seed.

## Build

One backend feature, under `[features] default` in `Cargo.toml`:

| Feature | Backend | Needs |
|---|---|---|
| `ifma`, `ifma-rayon` | `NTT3x42Ifma` | AVX-512F + IFMA + VL — **the reference's** |
| `avx512`, `avx512-rayon` | `NTT4x30Avx512` | AVX-512F |
| `avx`, `avx-rayon` | `NTT4x30Avx` | AVX2 + FMA |
| `neon`, `neon-rayon` | `NTT4x30Neon` | aarch64 |
| `ref` | `NTT4x30Ref` | nothing; the portable baseline |

`*-rayon` backends take `threads` from `config.jsonc`. All are exact NTT
backends; Poulpy's approximate FFT64 backends are not offered.

The platform builds with `cargo build --release` in the image
`poulpy-0-8-3` (x86-64 with AVX-512 IFMA; the target features are set by the
image). Locally, another machine builds another backend:

```sh
RUSTFLAGS="-C target-cpu=native" cargo build --release                       # whatever Cargo.toml selects
cargo build --release --no-default-features --features neon-rayon            # an Apple M-series
```

## Run locally

The loop and the types come from the signature (any change to them is not
measured); regenerate them with the language tool, then build:

```sh
fherma-lang emit --solution --envelope --out . --force ../ckks-eval-mod-s2c.fkl
cargo build --release --no-default-features --features neon-rayon
```

The binary writes a point directory the way the bundle does:

```sh
./target/release/fherma-solution make point \
  --point '{"N":65536,"log_delta":35,"output_k":720,"key_seed":0}' --seeds 1,2,3
./target/release/fherma-solution point
cat point/out/results.json
```

And the composition test, from the crate beside this one — one point, one
case, minutes and the memory of a bootstrap:

```sh
cd ../ckks-stages-check
cargo test --release --no-default-features --features neon-rayon -- --nocapture
```

Locally nothing judges the digest, and a digest made on another backend or
operating system will not equal the platform's: Poulpy encodes the DFT
matrices through `f64` and libm at `compile`, and the encoder's FFT differs
between backends at this scale (a Poulpy issue, being fixed). The platform
judges on its own machines, all running the same image and backend. Run
locally to see that it builds, runs, reaches the precision and passes the
composition test; leave the equality to the platform.

## What it costs

At this point, NEON + rayon × 8, Apple M3 Max: `setup` 67 s, `generate` about
80 s per case (the three stages before), one `run` about 1.8 s, `snr_bits`
21.1. Output per case 14 680 129 bytes. Memory as the bootstrapping's: the
keys alone are about 18 GB; plan for 32 GB and one process at a time.
## Submitting

Push this directory to a repository. On the platform, create an
implementation of `eval-mod` answering `s2c@1.0.0`: repository and
commit, harness language `rust`, runtime image `poulpy-0-8-3`. Run it. The
first run of a new point waits for the reference's own run to produce the
digests; after that a run is judged as it finishes.
