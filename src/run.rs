//! RUN — the function under measurement. The loop times this call and
//! nothing else.
//!
//! Reference: Poulpy's `ckks_eval_mod` on the preset's compiled EvalMod —
//! the Han–Ki even cosine polynomial (degree 30, 16 intervals) evaluated by
//! baby-step/giant-step over a power basis, then three rounds of the
//! double-angle formula, each a ct×ct squaring relinearised with the tensor
//! key — on one half. The orchestrator runs it on the real and the imaginary
//! halves; the stage is one of the two.
//!
//! A submission with its own algorithm replaces the body of `run`. It gets
//! its state from `init` and the input, and must leave the same bytes in the
//! output as this reference does.

use poulpy_ckks::api::CKKSEvalModOps;
use poulpy_ckks::layouts::BootstrappingKeys;
use poulpy_ckks::SetCKKSInfos;
use poulpy_hal::api::ScratchOwnedBorrow;

use crate::envelope::{Input, Output};
use crate::init::State;

pub fn run<'a>(state: &'a mut State<'_>, input: &Input) -> &'a Output {
    let context = state.context;
    let State { output, scratch, .. } = state;

    // EvalMod consumes width: it starts at the bootstrap width and leaves the
    // output narrower. The buffer is reused, so it is set back to the full
    // width before every run.
    output.set_k(context.preset.bootstrap_k().into());
    context
        .module
        .ckks_eval_mod(
            output,
            &input.ct,
            context.context.eval_mod(),
            context.keys.tensor_key(),
            &mut scratch.borrow(),
        )
        .expect("EvalMod");
    output
}
