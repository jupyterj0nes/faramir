//! Statistical primitives, the same ones masstin's graph-hunt uses, applied
//! to counts measured in the run itself:
//!
//!   * `empirical_p` / `upper_tail` — tail probability of an observation
//!     against the values the same statistic took on reference rows
//!   * `benjamini_hochberg` — false-discovery-rate control across rows
//!
//! No tuning constants live here. The only externally chosen number in the
//! whole hunt is alpha (`--alpha`, default 0.05).

/// Empirical p-value with the add-one correction:
/// (1 + #null values at least as extreme) / (1 + N). Never 0; with an
/// empty null it is 1 (nothing to compare with = no evidence).
pub fn empirical_p(at_least_as_extreme: usize, n_null: usize) -> f64 {
    (1.0 + at_least_as_extreme as f64) / (1.0 + n_null as f64)
}

/// Upper-tail empirical p of `x` against an ascending-sorted null sample.
pub fn upper_tail(sorted_null: &[f64], x: f64) -> f64 {
    let idx = sorted_null.partition_point(|v| *v < x);
    empirical_p(sorted_null.len() - idx, sorted_null.len())
}

/// Benjamini-Hochberg adjusted p-values (q-values), in input order.
pub fn benjamini_hochberg(ps: &[f64]) -> Vec<f64> {
    let m = ps.len();
    if m == 0 {
        return Vec::new();
    }
    let mut idx: Vec<usize> = (0..m).collect();
    idx.sort_by(|&a, &b| ps[a].partial_cmp(&ps[b]).unwrap_or(std::cmp::Ordering::Equal));
    let mut q = vec![1.0; m];
    let mut running = 1.0f64;
    for rank in (0..m).rev() {
        let i = idx[rank];
        let v = (ps[i] * m as f64 / (rank as f64 + 1.0)).min(1.0);
        running = running.min(v);
        q[i] = running;
    }
    q
}

/// Share of `total` that `count` is, as a tail probability: never 0, at most 1.
pub fn share(count: usize, total: usize) -> f64 {
    if total == 0 {
        return 1.0;
    }
    (count.max(1) as f64 / total as f64).min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bh_known() {
        let q = benjamini_hochberg(&[0.01, 0.04, 0.03, 0.2]);
        assert!((q[0] - 0.04).abs() < 1e-12);
        assert!((q[1] - 0.053_333_3).abs() < 1e-6);
        assert!((q[2] - 0.053_333_3).abs() < 1e-6);
        assert!((q[3] - 0.2).abs() < 1e-12);
        assert!(benjamini_hochberg(&[]).is_empty());
    }

    #[test]
    fn bh_monotone_and_bounded() {
        let ps = [0.5, 0.001, 0.2, 0.001, 0.9, 1.0];
        let q = benjamini_hochberg(&ps);
        for (p, qq) in ps.iter().zip(&q) {
            assert!(*qq >= *p - 1e-12 && *qq <= 1.0, "{p} -> {qq}");
        }
    }

    #[test]
    fn empirical() {
        let null = vec![0.0, 0.0, 1.0, 2.0, 5.0];
        assert!((upper_tail(&null, 5.0) - 2.0 / 6.0).abs() < 1e-12);
        assert!((upper_tail(&null, 6.0) - 1.0 / 6.0).abs() < 1e-12);
        assert!((upper_tail(&null, 0.0) - 1.0).abs() < 1e-12);
        assert!((upper_tail(&[], 3.0) - 1.0).abs() < 1e-12);
        assert!((empirical_p(0, 0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn shares() {
        assert_eq!(share(0, 0), 1.0);
        assert_eq!(share(0, 10), 0.1);
        assert_eq!(share(5, 10), 0.5);
        assert_eq!(share(20, 10), 1.0);
    }
}
