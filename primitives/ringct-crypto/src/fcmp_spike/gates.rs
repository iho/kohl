//! D2 go/no-go gates from `docs/fcmp-design.md`.

/// Design D2 quantitative gates (hard go/no-go for Path B headline).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GateSet {
    /// Max laptop prove time per input (ms).
    pub prove_ms_per_input: f64,
    /// Max native verify time per input (ms).
    pub verify_ms_per_input: f64,
    /// Max proof size per input (bytes).
    pub proof_bytes_per_input: usize,
    /// Whether the construction requires a trusted setup.
    pub trusted_setup: bool,
    /// Whether a written embedding security memo exists and is accepted.
    pub embedding_memo_ok: bool,
}

/// Consensus/design targets (D2).
pub const D2_GATES: GateSet = GateSet {
    prove_ms_per_input: 30_000.0,
    verify_ms_per_input: 25.0,
    proof_bytes_per_input: 16 * 1024,
    trusted_setup: false,
    embedding_memo_ok: true,
};

/// Engineering goals from D9 (softer than D2 hard fail).
pub const D9_ENGINEERING: GateSet = GateSet {
    prove_ms_per_input: 30_000.0,
    verify_ms_per_input: 25.0,
    proof_bytes_per_input: 4 * 1024, // design "≤ 2–4 KiB" goal band
    trusted_setup: false,
    embedding_memo_ok: true,
};

#[derive(Clone, Debug, PartialEq)]
pub struct GateResult {
    pub prove_ok: bool,
    pub verify_ok: bool,
    pub size_ok: bool,
    pub setup_ok: bool,
    pub embedding_ok: bool,
    pub passed: bool,
    pub failures: alloc::vec::Vec<&'static str>,
}

/// Compare a candidate measurement set against the D2 (or other) thresholds.
///
/// For boolean fields on `measured`:
/// * `trusted_setup`: must be **false** to pass (no trusted setup).
/// * `embedding_memo_ok`: must be **true** to pass.
///
/// Numeric fields on `measured` are the **observed** costs; they must be
/// ≤ the corresponding threshold on `threshold`.
pub fn evaluate_gates(measured: &GateSet, threshold: &GateSet) -> GateResult {
    let mut failures = alloc::vec::Vec::new();

    let prove_ok = measured.prove_ms_per_input <= threshold.prove_ms_per_input;
    if !prove_ok {
        failures.push("prove_ms_per_input exceeds gate");
    }
    let verify_ok = measured.verify_ms_per_input <= threshold.verify_ms_per_input;
    if !verify_ok {
        failures.push("verify_ms_per_input exceeds gate");
    }
    let size_ok = measured.proof_bytes_per_input <= threshold.proof_bytes_per_input;
    if !size_ok {
        failures.push("proof_bytes_per_input exceeds gate");
    }
    // Pass setup gate iff construction does not need trusted setup.
    let setup_ok = !measured.trusted_setup;
    if !setup_ok {
        failures.push("trusted setup required (rejected by D2)");
    }
    let embedding_ok = measured.embedding_memo_ok;
    if !embedding_ok {
        failures.push("embedding security memo incomplete");
    }

    let passed = prove_ok && verify_ok && size_ok && setup_ok && embedding_ok;
    GateResult {
        prove_ok,
        verify_ok,
        size_ok,
        setup_ok,
        embedding_ok,
        passed,
        failures,
    }
}

/// Path A tree-maintenance micro-benchmarks are not membership proofs; they
/// always "pass" D2 membership gates only in the sense that maintenance is
/// cheap. Membership ZK remains unmeasured until PR-5a.
#[derive(Clone, Debug)]
pub struct PathAMaintenanceReport {
    pub grow_ns_per_leaf: f64,
    pub admit_ns_per_leaf: f64,
    pub root_ns_at_n: f64,
    pub n_leaves: u64,
    pub transparent_path_bytes: usize,
    pub note: &'static str,
}

impl PathAMaintenanceReport {
    pub fn maintenance_acceptable(&self) -> bool {
        // Extremely loose: admit+grow should be well under 1 ms/leaf for runtime.
        self.grow_ns_per_leaf < 1_000_000.0 && self.admit_ns_per_leaf < 1_000_000.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn d2_self_passes() {
        // A measurement exactly at the gate should pass.
        let r = evaluate_gates(&D2_GATES, &D2_GATES);
        assert!(r.passed, "{:?}", r.failures);
    }

    #[test]
    fn slow_verify_fails() {
        let mut m = D2_GATES;
        m.verify_ms_per_input = 40.0;
        let r = evaluate_gates(&m, &D2_GATES);
        assert!(!r.passed);
        assert!(!r.verify_ok);
    }

    #[test]
    fn trusted_setup_fails() {
        let mut m = D2_GATES;
        m.trusted_setup = true;
        let r = evaluate_gates(&m, &D2_GATES);
        assert!(!r.setup_ok);
        assert!(!r.passed);
    }
}
