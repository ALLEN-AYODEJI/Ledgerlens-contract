//! Tests for governed per-wallet cool-off exemptions (issue #1425).
//!
//! Covers: two-person granting, mandatory bounded expiry, no silent renewal,
//! lapse-to-default, each mechanism lifting only itself, the scoped embargo
//! read, restricted record reads, and that ordinary consumers observe no
//! difference from an exemption's existence.

use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger as _},
    Address, BytesN, Env, Symbol, Vec,
};

use crate::{
    constants, Error, ExemptMechanism, LedgerLensScoreContract, LedgerLensScoreContractClient,
};

const START_TS: u64 = 1_700_000_000;
const COOLDOWN: u64 = 3_601;
const DAY: u64 = 86_400;

struct Ctx<'a> {
    env: Env,
    client: LedgerLensScoreContractClient<'a>,
    admin: Address,
    a1: Address,
    a2: Address,
}

/// Contract with a two-member admin set (`a1`, `a2`) alongside the root admin.
fn setup<'a>() -> Ctx<'a> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START_TS);
    let contract_id = env.register_contract(None, LedgerLensScoreContract);
    let client = LedgerLensScoreContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let service = Address::generate(&env);
    client.initialize(&admin, &service);
    let a1 = Address::generate(&env);
    let a2 = Address::generate(&env);
    let root = Vec::from_array(&env, [admin.clone()]);
    client.add_admin_signer(&root, &a1);
    client.add_admin_signer(&root, &a2);
    Ctx { env, client, admin, a1, a2 }
}

impl Ctx<'_> {
    fn both(&self) -> Vec<Address> {
        Vec::from_array(&self.env, [self.a1.clone(), self.a2.clone()])
    }

    fn gov_ref(&self) -> BytesN<32> {
        BytesN::from_array(&self.env, &[7u8; 32])
    }

    fn grant(&self, wallet: &Address, m: ExemptMechanism, disclose_to: Option<Address>) {
        self.client.grant_cool_off_exemption(
            &self.both(),
            wallet,
            &m,
            &self.gov_ref(),
            &(self.env.ledger().timestamp() + DAY),
            &disclose_to,
        );
    }

    fn try_submit(&self, wallet: &Address, p: &Symbol, score: u32) -> Result<(), Error> {
        match self.client.try_submit_score(
            &Vec::new(&self.env),
            wallet,
            p,
            &score,
            &false,
            &false,
            &self.env.ledger().timestamp(),
            &90,
            &1,
            &None,
        ) {
            Ok(_) => Ok(()),
            Err(Ok(e)) => Err(e),
            Err(Err(_)) => panic!("invoke error"),
        }
    }

    fn advance(&self, secs: u64) {
        self.env.ledger().with_mut(|l| l.timestamp += secs);
    }

    fn enable_floor(&self) {
        self.client.set_score_floor_policy(
            &Vec::from_array(&self.env, [self.admin.clone()]),
            &true,
            &80,
            &50,
        );
    }
}

// ── Granting and two-person authorisation ───────────────────────────────────

#[test]
fn grant_requires_two_distinct_admin_set_members() {
    let c = setup();
    let wallet = Address::generate(&c.env);
    let expiry = START_TS + DAY;
    let only_a1 = Vec::from_array(&c.env, [c.a1.clone()]);
    let a1_twice = Vec::from_array(&c.env, [c.a1.clone(), c.a1.clone()]);
    for signers in [only_a1, a1_twice] {
        assert_eq!(
            c.client.try_grant_cool_off_exemption(
                &signers,
                &wallet,
                &ExemptMechanism::RateLimit,
                &c.gov_ref(),
                &expiry,
                &None,
            ),
            Err(Ok(Error::InsufficientAdminSigners))
        );
    }
    c.client.grant_cool_off_exemption(
        &c.both(),
        &wallet,
        &ExemptMechanism::RateLimit,
        &c.gov_ref(),
        &expiry,
        &None,
    );
    let rec =
        c.client.get_cool_off_exemption(&c.admin, &wallet, &ExemptMechanism::RateLimit).unwrap();
    assert_eq!(rec.approvers, c.both());
    assert_eq!(rec.expires_at, expiry);
    assert_eq!(rec.granted_at, START_TS);
    assert_eq!(rec.governance_ref, c.gov_ref());
}

#[test]
fn single_admin_deployment_cannot_grant() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, LedgerLensScoreContract);
    let client = LedgerLensScoreContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &Address::generate(&env));
    assert_eq!(
        client.try_grant_cool_off_exemption(
            &Vec::from_array(&env, [admin.clone(), admin.clone()]),
            &Address::generate(&env),
            &ExemptMechanism::Embargo,
            &BytesN::from_array(&env, &[1u8; 32]),
            &(env.ledger().timestamp() + DAY),
            &None,
        ),
        Err(Ok(Error::InsufficientAdminSigners))
    );
}

#[test]
fn expiry_is_mandatory_and_bounded() {
    let c = setup();
    let wallet = Address::generate(&c.env);
    for expiry in [0, START_TS, START_TS + constants::MAX_COOL_OFF_EXEMPTION_SECS + 1] {
        assert_eq!(
            c.client.try_grant_cool_off_exemption(
                &c.both(),
                &wallet,
                &ExemptMechanism::ScoreFloor,
                &c.gov_ref(),
                &expiry,
                &None,
            ),
            Err(Ok(Error::InvalidCoolOffExemptionExpiry))
        );
    }
    c.client.grant_cool_off_exemption(
        &c.both(),
        &wallet,
        &ExemptMechanism::ScoreFloor,
        &c.gov_ref(),
        &(START_TS + constants::MAX_COOL_OFF_EXEMPTION_SECS),
        &None,
    );
}

#[test]
fn no_silent_renewal_and_regrant_after_lapse() {
    let c = setup();
    let wallet = Address::generate(&c.env);
    c.grant(&wallet, ExemptMechanism::RateLimit, None);
    assert_eq!(
        c.client.try_grant_cool_off_exemption(
            &c.both(),
            &wallet,
            &ExemptMechanism::RateLimit,
            &c.gov_ref(),
            &(START_TS + 2 * DAY),
            &None,
        ),
        Err(Ok(Error::CoolOffExemptionAlreadyActive))
    );
    // A different mechanism for the same wallet is an independent record.
    c.grant(&wallet, ExemptMechanism::ScoreFloor, None);

    c.advance(DAY);
    assert_eq!(
        c.client.get_cool_off_exemption(&c.admin, &wallet, &ExemptMechanism::RateLimit),
        None
    );
    c.grant(&wallet, ExemptMechanism::RateLimit, None);
}

#[test]
fn revoke_restores_default_and_requires_a_record() {
    let c = setup();
    let wallet = Address::generate(&c.env);
    let p = symbol_short!("XLM_USDC");
    c.try_submit(&wallet, &p, 40).unwrap();
    c.grant(&wallet, ExemptMechanism::RateLimit, None);
    c.try_submit(&wallet, &p, 41).unwrap();

    let root = Vec::from_array(&c.env, [c.admin.clone()]);
    c.client.revoke_cool_off_exemption(&root, &wallet, &ExemptMechanism::RateLimit);
    assert_eq!(c.try_submit(&wallet, &p, 42), Err(Error::RateLimitExceeded));
    assert_eq!(
        c.client.try_revoke_cool_off_exemption(&root, &wallet, &ExemptMechanism::RateLimit),
        Err(Ok(Error::CoolOffExemptionNotFound))
    );
}

// ── Each mechanism lifts only itself ─────────────────────────────────────────

#[test]
fn rate_limit_exemption_lifts_cooldown_only_and_lapses() {
    let c = setup();
    c.enable_floor();
    let wallet = Address::generate(&c.env);
    let p = symbol_short!("XLM_USDC");
    c.try_submit(&wallet, &p, 90).unwrap();
    assert_eq!(c.try_submit(&wallet, &p, 85), Err(Error::RateLimitExceeded));

    c.grant(&wallet, ExemptMechanism::RateLimit, None);
    c.try_submit(&wallet, &p, 85).unwrap();
    assert_eq!(c.client.get_score(&wallet, &p).score, 85);
    // The floor is a different mechanism and still applies.
    assert_eq!(c.try_submit(&wallet, &p, 10), Err(Error::InvalidScore));

    // Lapse: back to the normal cooldown with no transaction.
    c.advance(DAY);
    c.try_submit(&wallet, &p, 86).unwrap();
    assert_eq!(c.try_submit(&wallet, &p, 87), Err(Error::RateLimitExceeded));
}

#[test]
fn score_floor_exemption_lifts_floor_only_and_stores_score_verbatim() {
    let c = setup();
    c.enable_floor();
    let wallet = Address::generate(&c.env);
    let p = symbol_short!("XLM_USDC");
    c.try_submit(&wallet, &p, 90).unwrap();
    c.advance(COOLDOWN);
    assert_eq!(c.try_submit(&wallet, &p, 10), Err(Error::InvalidScore));

    c.grant(&wallet, ExemptMechanism::ScoreFloor, None);
    c.advance(COOLDOWN);
    c.try_submit(&wallet, &p, 10).unwrap();
    let stored = c.client.get_score(&wallet, &p);
    assert_eq!(stored.score, 10);
    assert_eq!(stored.confidence, 90);
    // The cooldown is a different mechanism and still applies.
    assert_eq!(c.try_submit(&wallet, &p, 11), Err(Error::RateLimitExceeded));

    // Lapse: the floor applies again (the peak is still 90).
    c.advance(DAY);
    assert_eq!(c.try_submit(&wallet, &p, 5), Err(Error::InvalidScore));
}

#[test]
fn embargo_exemption_serves_only_the_scoped_party_until_lapse() {
    let c = setup();
    let wallet = Address::generate(&c.env);
    let party = Address::generate(&c.env);
    let stranger = Address::generate(&c.env);
    let p = symbol_short!("XLM_USDC");
    c.try_submit(&wallet, &p, 70).unwrap();
    c.client.set_score_embargo(&wallet, &None);
    c.grant(&wallet, ExemptMechanism::Embargo, Some(party.clone()));

    assert_eq!(c.client.get_score_under_exemption(&party, &wallet, &p).score, 70);
    // Everyone else sees exactly the embargo.
    assert_eq!(
        c.client.try_get_score_under_exemption(&stranger, &wallet, &p),
        Err(Ok(Error::ScoreEmbargoed))
    );
    assert_eq!(c.client.try_get_score(&wallet, &p), Err(Ok(Error::ScoreEmbargoed)));
    assert!(c.client.is_embargoed(&wallet));

    c.advance(DAY);
    assert_eq!(
        c.client.try_get_score_under_exemption(&party, &wallet, &p),
        Err(Ok(Error::ScoreEmbargoed))
    );
}

#[test]
fn exemption_record_is_readable_only_by_admins_and_the_scoped_party() {
    let c = setup();
    let wallet = Address::generate(&c.env);
    let party = Address::generate(&c.env);
    let stranger = Address::generate(&c.env);
    let m = ExemptMechanism::Embargo;
    // Same answer for a stranger whether or not a record exists.
    assert_eq!(
        c.client.try_get_cool_off_exemption(&stranger, &wallet, &m),
        Err(Ok(Error::Unauthorized))
    );
    c.grant(&wallet, m, Some(party.clone()));
    assert_eq!(
        c.client.try_get_cool_off_exemption(&stranger, &wallet, &m),
        Err(Ok(Error::Unauthorized))
    );
    assert!(c.client.get_cool_off_exemption(&party, &wallet, &m).is_some());
    assert!(c.client.get_cool_off_exemption(&c.a1, &wallet, &m).is_some());
}

// ── Ordinary consumers see no difference ─────────────────────────────────────

/// Everything an ordinary consumer can observe about `wallet` on `p`.
fn consumer_view(
    c: &Ctx,
    wallet: &Address,
    p: &Symbol,
) -> (std::vec::Vec<bool>, std::vec::Vec<bool>, bool, std::string::String, std::string::String) {
    let gates = (0..=100).step_by(5).map(|t| c.client.query_risk_gate(wallet, p, &t)).collect();
    let conf_gates = (0..=100)
        .step_by(10)
        .map(|t| c.client.query_risk_gate_with_confidence(wallet, p, &t, &50))
        .collect();
    let score = std::format!("{:?}", c.client.try_get_score(wallet, p));
    let agg = std::format!("{:?}", c.client.try_get_aggregate_score(wallet));
    (gates, conf_gates, c.client.is_embargoed(wallet), score, agg)
}

#[test]
fn consumer_gate_decisions_identical_with_or_without_exemptions() {
    for embargoed in [false, true] {
        let c = setup();
        let wallet = Address::generate(&c.env);
        let party = Address::generate(&c.env);
        let p = symbol_short!("XLM_USDC");
        c.try_submit(&wallet, &p, 64).unwrap();
        if embargoed {
            c.client.set_score_embargo(&wallet, &None);
        }
        let before = consumer_view(&c, &wallet, &p);
        c.grant(&wallet, ExemptMechanism::RateLimit, None);
        c.grant(&wallet, ExemptMechanism::ScoreFloor, None);
        c.grant(&wallet, ExemptMechanism::Embargo, Some(party));
        assert_eq!(consumer_view(&c, &wallet, &p), before, "embargoed = {embargoed}");
    }
}
