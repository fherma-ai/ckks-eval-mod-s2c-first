# CKKS EvalMod, S2C-first — reference implementation

A submission to `eval-mod/s2c@1.0.0` on FHERMA: the EvalMod stage of Poulpy's S2C-first CKKS bootstrapping — the homomorphic modular reduction — on one of the two halves, timed on its own. Poulpy 0.8.3, toolchain
`nightly-2026-05-14`.

This repository is the reference implementation: the answer every
submission is compared to, and the harness every submission is measured in.

## Attribution

[Poulpy](https://github.com/poulpy-fhe/poulpy) is an open-source homomorphic
encryption library developed by the Poulpy project ([poulpy.dev](https://www.poulpy.dev/))
and released under the Apache License 2.0. The bootstrapping, its parameter
set and its implementation are Poulpy's. This repository calls Poulpy through
its public API in order to measure it on [FHERMA](https://www.fherma.io); it
claims no authorship of the library or of the algorithm, and FHERMA is not
affiliated with the Poulpy project.

## What the stage does

| | |
|---|---|
| Input | the real half CoeffsToSlots leaves (1184 bits): slot `j` holds the real part of the message's slot `j` plus an integer multiple of the raised-from modulus; made from `case_seed` through the three reference stages before |
| Operation | `ckks_eval_mod` on the preset's EvalMod: the Han–Ki even cosine polynomial (degree 30, 16 intervals) by baby-step/giant-step over a power basis, then three double-angle rounds, each a ciphertext squaring relinearised with the tensor key |
| Output | one ciphertext at 720 bits, scale 2³⁵, slot `j` holding the real part of the message's slot `j`, the integer parts removed. The bootstrap runs this on both halves and adds `re + i·im` |
| Measured on the platform | about 1.1 s (Intel Xeon 6776P, 24 cores, AVX-512 IFMA + Rayon) for one half |

## What to change to make it faster

Three files are yours; everything else is the specification's and is laid
over your repository at every measurement, so a change to it is not measured.

| File | Role |
|---|---|
| `src/run.rs` | EvalMod into the output buffer. **The only thing timed.** Replace its body with your own algorithm; the output must be the same bytes. |
| `src/init.rs` | your setup over the point and the keys — buffers, plans, keys onto a GPU. Never sees a case. Not timed. |
| `src/free.rs` | your teardown. Not timed. |
| `Cargo.toml` | the Poulpy backend, one cargo feature: `ref`, `avx`, `avx512`, `ifma`, `neon`, each with a `-rayon` variant. The reference builds `ifma-rayon`. |
| `config.jsonc` | `threads` for a `-rayon` backend; `0` is every core. |

`src/envelope/` (key generation from the seed, the case from its seed, the
canonical bytes, the precision check) and the generated `src/main.rs`,
`src/fherma.rs` are the specification's. Correctness is the sha256 of the
output: it must equal the reference's for the same point and seed, with no
tolerance. Precision is reported beside the time, not judged.

## Build, run, submit

```sh
cargo build --release                                                  # the platform's image: x86-64, AVX-512 IFMA
cargo build --release --no-default-features --features neon-rayon      # on an Apple M-series
./target/release/fherma-solution make point --point '{"N":65536,"log_delta":35,"output_k":720,"key_seed":0}' --seeds 1,2
./target/release/fherma-solution point && cat point/out/results.json
```

The keys alone are about 18 GB: plan for 32 GB and one process at a time. A digest made on another backend or operating system will not equal
the platform's; the platform judges on its own machines.

To submit: `fherma implementation init eval-mod/s2c@1.0.0` writes this
layout for you; push your repository and register the commit on the
platform. See the [documentation](https://www.fherma.io/docs/solution-kinds).
