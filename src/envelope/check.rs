//! CHECK — the output's precision against the message. NOT measured as
//! score; timed apart and reported as metrics.
//!
//! Correctness on the platform is the digest. This is the other reading of an
//! EvalMod: with the integer parts `I·q` removed, slot `j` of the output holds
//! the real part of the message's slot `j` — the coefficient CoeffsToSlots
//! brought there, which SlotsToCoeffs had made of that value. The measure is
//! the scale-invariant signal-to-noise ratio in bits between the decoded real
//! slots and the message's real parts, Poulpy's `snr_bits` (its
//! `EVALMOD-PREC`). The specification's file; it has the secret because
//! `setup` does.

use poulpy_ckks::api::{CKKSDecryptOps, CKKSEncodingHostOps};
use poulpy_ckks::layouts::CKKSModuleAlloc;
use poulpy_ckks::{CKKSInfos, CKKSMeta, SetCKKSInfos, SlotsKind};
use poulpy_core::layouts::{GLWESecretPrepared, LWEInfos};
use poulpy_hal::api::ScratchOwnedBorrow;
use poulpy_hal::layouts::{Backend, Module, ScratchArena};

use crate::envelope::backend::BE;

use super::keys::{Context, Ct};

/// Plaintext budget bits above `log_delta` a ciphertext is decrypted at, as
/// in Poulpy's driver.
const LOG_BUDGET: usize = 8;

/// Signal-to-noise ratio in bits of the output's real slots against the
/// message's real parts.
pub fn precision(state: &Context, output: &Ct, want_re: &[f64]) -> f64 {
    let mut arena = state.scratch.borrow_mut();
    let got = real_slots(&state.module, &mut arena.borrow(), &state.sk, output, want_re.len());
    snr_bits(&got, want_re)
}

/// The real part of every slot of one output half.
fn real_slots(
    module: &Module<BE>,
    scratch: &mut ScratchArena<'_, BE>,
    sk: &GLWESecretPrepared<<BE as Backend>::OwnedBuf, BE>,
    ct: &Ct,
    m: usize,
) -> Vec<f64> {
    let (log_delta, log_budget) = budget(ct);
    let mut pt = module.ckks_pt_vec_alloc(ct.base2k(), (log_delta + log_budget).into());
    pt.set_meta(CKKSMeta {
        log_sparsity: 0,
        log_delta,
        slots: SlotsKind::Complex,
    });
    module
        .ckks_decrypt(&mut pt, ct, sk, scratch)
        .expect("decrypt a half for the precision check");
    let (mut re, mut im) = (vec![0f64; m], vec![0f64; m]);
    module
        .ckks_decode_reim_into(&pt, &mut re, &mut im, scratch)
        .expect("decode a half for the precision check");
    re
}

/// `(log_delta, log_budget)` to decrypt at: a small budget above the scale,
/// capped so `log_delta + log_budget <= 127` fits the decode codec.
fn budget(ct: &Ct) -> (usize, usize) {
    let log_delta = ct.log_delta();
    let log_budget = ct
        .log_budget()
        .min(LOG_BUDGET)
        .min(127usize.saturating_sub(log_delta));
    (log_delta, log_budget)
}

/// Scale-invariant signal-to-noise ratio in bits, Poulpy's `snr_bits`: the
/// best global scale `s` between `got` and `want`, then
/// `-0.5·log2(||got − s·want||² / ||s·want||²)`. Measures how well the shape
/// is recovered, whatever the per-step scale bookkeeping.
fn snr_bits(got: &[f64], want: &[f64]) -> f64 {
    let dot_gw: f64 = got.iter().zip(want).map(|(g, w)| g * w).sum();
    let dot_ww: f64 = want.iter().map(|w| w * w).sum();
    let s = if dot_ww > 0.0 { dot_gw / dot_ww } else { 0.0 };
    let err2: f64 = got.iter().zip(want).map(|(g, w)| (g - s * w).powi(2)).sum();
    let sig2: f64 = want.iter().map(|w| (s * w).powi(2)).sum();
    if err2 <= 0.0 || sig2 <= 0.0 {
        return f64::INFINITY;
    }
    -0.5 * (err2 / sig2).log2()
}
