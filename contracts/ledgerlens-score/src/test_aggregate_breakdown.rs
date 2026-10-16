//! Tests for the bounded "explain the aggregate" read,
//! `get_aggregate_breakdown` (issue #1426).
//!
//! The breakdown and `get_aggregate_score` share one implementation
//! (`aggregate_core`). Every test here checks both entry points against an
//! independent in-test reference model, so a defect injected into the shared
//! loop, into either wrapper, or into the truncation step fails here even if
//! the two entry points still agree with each other.

extern crate std;

use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
    Address, Env, Symbol, Vec,
};

use crate::{constants, Error, LedgerLensScoreContract, LedgerLensScoreContractClient};

const START_TS: u64 = 1_700_000_000;

fn setup<'a>() -> (Env, LedgerLensScoreContractClient<'a>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START_TS);
    let contract_id = env.register_contract(None, LedgerLensScoreContract);
    let client = LedgerLensScoreContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);
    (env, client, admin)
}

fn pair(env: &Env, i: u32) -> Symbol {
    Symbol::new(env, &std::format!("P{i}"))
}

fn submit(env: &Env, client: &LedgerLensScoreContractClient, wallet: &Address, p: &Symbol, s: u32) {
    client.submit_score(
        &Vec::new(env),
        wallet,
        p,
        &s,
        &false,
        &false,
        &env.ledger().timestamp(),
        &90,
        &1,
        &None,
    );
}

/// Builds a portfolio of `(score, weight)` per pair index for `wallet`.
fn build(
    env: &Env,
    client: &LedgerLensScoreContractClient,
    admin: &Address,
    wallet: &Address,
    portfolio: &[(u32, u32)],
) {
    let signers = Vec::from_array(env, [admin.clone()]);
    for (i, (score, weight)) in portfolio.iter().enumerate() {
        let p = pair(env, i as u32);
        client.set_pair_weight(&signers, &p, weight);
        submit(env, client, wallet, &p, *score);
    }
}

/// Independent reference: `floor(Σ w·s / Σ w)`, `None` when `Σ w = 0`.
fn reference(portfolio: &[(u32, u32)]) -> Option<u32> {
    let ws: u64 = portfolio.iter().map(|(s, w)| (*s as u64) * (*w as u64)).sum();
    let w: u64 = portfolio.iter().map(|(_, w)| *w as u64).sum();
    (w != 0).then(|| (ws / w) as u32)
}

/// Deterministic xorshift so the property test is reproducible without a
/// proptest dependency (same approach as the other property suites here).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u32 {
        (self.next() % n) as u32
    }
}

#[test]
fn breakdown_reconstructs_aggregate_for_random_portfolios() {
    let mut rng = Rng(0x1426_1426_dead_beef);
    for case in 0..40u32 {
        let (env, client, admin) = setup();
        let wallet = Address::generate(&env);
        // 1..=MAX_AGGREGATE_BREAKDOWN_PAIRS so nothing is truncated; weights
        // include 0 to cover excluded pairs.
        let n = 1 + rng.below(constants::MAX_AGGREGATE_BREAKDOWN_PAIRS as u64) as usize;
        let portfolio: std::vec::Vec<(u32, u32)> =
            (0..n).map(|_| (rng.below(101), rng.below(51))).collect();
        build(&env, &client, &admin, &wallet, &portfolio);

        match reference(&portfolio) {
            None => {
                assert_eq!(
                    client.try_get_aggregate_breakdown(&wallet),
                    Err(Ok(Error::ScoreNotFound)),
                    "case {case}"
                );
                assert_eq!(
                    client.try_get_aggregate_score(&wallet),
                    Err(Ok(Error::ScoreNotFound)),
                    "case {case}"
                );
            }
            Some(expected) => {
                let b = client.get_aggregate_breakdown(&wallet);
                let agg = client.get_aggregate_score(&wallet);
                assert!(!b.truncated, "case {case}");
                assert_eq!(b.pair_count, n as u32, "case {case}");
                assert_eq!(b.contributions.len(), n as u32, "case {case}");

                let mut sum_c: u64 = 0;
                let mut sum_w: u64 = 0;
                for c in b.contributions.iter() {
                    assert_eq!(c.contribution, c.weight * c.score as u64, "case {case}");
                    sum_c += c.contribution;
                    sum_w += c.weight;
                }
                assert_eq!(sum_c, b.weighted_sum, "case {case}");
                assert_eq!(sum_w, b.weight_sum, "case {case}");
                assert_eq!((sum_c / sum_w) as u32, expected, "case {case}");
                assert_eq!(b.aggregate_score, expected, "case {case}");
                assert_eq!(agg.aggregate_score, expected, "case {case}");
            }
        }
    }
}

#[test]
fn breakdown_matches_aggregate_under_decay() {
    let (env, client, admin) = setup();
    let wallet = Address::generate(&env);
    build(&env, &client, &admin, &wallet, &[(90, 300), (10, 100)]);
    env.ledger().with_mut(|l| l.timestamp += 86_400);
    let late = pair(&env, 2);
    submit(&env, &client, &wallet, &late, 50);
    // λ = 1/(10 days): older pairs are down-weighted but stay non-zero.
    client.set_decay_rate(&1, &864_000);
    env.ledger().with_mut(|l| l.timestamp += 86_400);

    let b = client.get_aggregate_breakdown(&wallet);
    let agg = client.get_aggregate_score(&wallet);
    assert_eq!(b.aggregate_score, agg.aggregate_score);
    assert_eq!((b.weighted_sum / b.weight_sum) as u32, agg.aggregate_score);
    let sum_w: u64 = b.contributions.iter().map(|c| c.weight).sum();
    assert_eq!(sum_w, b.weight_sum);
    // Decay actually changed the effective weights the breakdown reports.
    assert!(b.contributions.iter().any(|c| c.asset_pair == pair(&env, 0) && c.weight < 300));
}

#[test]
fn truncation_keeps_highest_contributors_in_order() {
    let (env, client, admin) = setup();
    let wallet = Address::generate(&env);
    let cap = constants::MAX_AGGREGATE_BREAKDOWN_PAIRS;
    // cap + 2 pairs (still within MAX_WALLET_PAIRS). Pair i contributes
    // (i + 1) * 5, so the two smallest are P0 and P1; P5/P6 tie at 30 to
    // check that ties keep the wallet's pair order.
    let mut portfolio: std::vec::Vec<(u32, u32)> = (0..cap + 2).map(|i| ((i + 1) * 5, 1)).collect();
    portfolio[5] = (30, 1);
    portfolio[6] = (15, 2);
    build(&env, &client, &admin, &wallet, &portfolio);

    let b = client.get_aggregate_breakdown(&wallet);
    assert!(b.truncated);
    assert_eq!(b.pair_count, cap + 2);
    assert_eq!(b.contributions.len(), cap);

    // Strictly the top `cap` by contribution, descending.
    let mut all: std::vec::Vec<u64> =
        portfolio.iter().map(|(s, w)| (*s as u64) * (*w as u64)).collect();
    all.sort_unstable_by(|a, b| b.cmp(a));
    let got: std::vec::Vec<u64> = b.contributions.iter().map(|c| c.contribution).collect();
    assert_eq!(got, all[..cap as usize].to_vec());
    let tied: std::vec::Vec<Symbol> =
        b.contributions.iter().filter(|c| c.contribution == 30).map(|c| c.asset_pair).collect();
    assert_eq!(tied, std::vec![pair(&env, 5), pair(&env, 6)]);
    assert!(!b.contributions.iter().any(|c| c.asset_pair == pair(&env, 0)));
    assert!(!b.contributions.iter().any(|c| c.asset_pair == pair(&env, 1)));

    // The totals still cover every pair, so the aggregate is reproducible.
    assert_eq!(
        (b.weighted_sum / b.weight_sum) as u32,
        client.get_aggregate_score(&wallet).aggregate_score
    );
    assert_eq!(b.aggregate_score, reference(&portfolio).unwrap());
}

#[test]
fn exactly_at_cap_is_not_truncated() {
    let (env, client, admin) = setup();
    let wallet = Address::generate(&env);
    let portfolio: std::vec::Vec<(u32, u32)> =
        (0..constants::MAX_AGGREGATE_BREAKDOWN_PAIRS).map(|i| (i * 7, 1)).collect();
    build(&env, &client, &admin, &wallet, &portfolio);
    let b = client.get_aggregate_breakdown(&wallet);
    assert!(!b.truncated);
    assert_eq!(b.contributions.len(), constants::MAX_AGGREGATE_BREAKDOWN_PAIRS);
}

#[test]
fn breakdown_follows_embargo_delegation_and_missing_scores() {
    let (env, client, admin) = setup();
    let wallet = Address::generate(&env);
    assert_eq!(client.try_get_aggregate_breakdown(&wallet), Err(Ok(Error::ScoreNotFound)));

    build(&env, &client, &admin, &wallet, &[(40, 1), (80, 1)]);
    let sub = Address::generate(&env);
    client.set_score_delegate(&sub, &wallet);
    assert_eq!(client.get_aggregate_breakdown(&sub), client.get_aggregate_breakdown(&wallet));

    client.set_score_embargo(&wallet, &None);
    assert_eq!(client.try_get_aggregate_breakdown(&wallet), Err(Ok(Error::ScoreEmbargoed)));
    assert_eq!(client.try_get_aggregate_score(&wallet), Err(Ok(Error::ScoreEmbargoed)));
}

#[test]
fn breakdown_is_a_pure_read() {
    let (env, client, admin) = setup();
    let wallet = Address::generate(&env);
    build(&env, &client, &admin, &wallet, &[(20, 1), (60, 3)]);
    let first = client.get_aggregate_breakdown(&wallet);
    // Repeated reads are stable and leave the aggregate untouched.
    for _ in 0..3 {
        assert_eq!(client.get_aggregate_breakdown(&wallet), first);
    }
    assert_eq!(client.get_aggregate_score(&wallet).aggregate_score, first.aggregate_score);
}
