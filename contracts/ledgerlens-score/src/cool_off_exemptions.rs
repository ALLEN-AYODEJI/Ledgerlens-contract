//! Governed per-wallet cool-off exemptions (issue #1425).
//!
//! A wallet under active legal process (for example a court order requiring
//! continued, unrestricted read access by one named party) may need a
//! narrowly scoped exemption from exactly one per-wallet mechanism — the
//! submission rate limit, the score embargo, or the score floor — without
//! that exemption reading as a generic "safe" signal to anyone else.
//!
//! Properties, each enforced here rather than by convention:
//!
//! - **One mechanism per record.** A record is keyed by
//!   `(wallet, ExemptMechanism)`; it lifts that check and nothing else.
//! - **Never touches score or confidence.** No function in this file writes
//!   a `RiskScore`. A score-floor or rate-limit exemption only lets a
//!   submission through that the check would have rejected; the stored score
//!   is exactly what was submitted.
//! - **Invisible to ordinary consumers.** Gates (`query_risk_gate*`),
//!   `get_score`, aggregates and the embargo reads are not consulted for
//!   exemptions. An embargo exemption is honoured only by
//!   [`get_score_under_exemption`](LedgerLensScoreContract::get_score_under_exemption),
//!   and only for the record's `disclose_to` party; every other caller of
//!   that function gets exactly what `get_score` would have returned.
//! - **Two-person authorisation.** A grant needs at least two distinct
//!   members of the admin set to authorise the same transaction, regardless
//!   of the configured admin threshold. Single-admin (legacy) deployments
//!   cannot grant exemptions at all.
//! - **Mandatory expiry, no silent renewal.** `expires_at` must be in the
//!   future and at most `MAX_COOL_OFF_EXEMPTION_SECS` ahead; granting over an
//!   unexpired record is rejected. A lapsed record is ignored by every check
//!   (`storage::active_cool_off_exemption`), so behaviour falls back to
//!   normal at `expires_at` with no transaction required.
//! - **Minimal on-chain footprint.** The legal context stays off-chain; the
//!   record carries only a 32-byte `governance_ref` commitment to the
//!   authorising governance action, the approvers, the times, and the
//!   optional disclosure party. Events publish existence only.
//!
//! See `docs/privacy-model.md` § Cool-off exemptions.

use soroban_sdk::{contractimpl, Address, BytesN, Env, Symbol, Vec};

use crate::errors::Error;
use crate::types::{CoolOffExemption, ExemptMechanism, RiskScore};
use crate::{constants, events, storage, LedgerLensScoreContract, LedgerLensScoreContractClient};

#[contractimpl]
impl LedgerLensScoreContract {
    /// Governance (two-person): exempts `wallet` from `mechanism` until
    /// `expires_at` (ledger timestamp, exclusive).
    ///
    /// `governance_ref` is a 32-byte commitment (e.g. a SHA-256) to the
    /// authorising governance action and its off-chain legal record.
    /// `disclose_to`, when set, is the one party that may read the record via
    /// [`get_cool_off_exemption`](Self::get_cool_off_exemption) and, for an
    /// `Embargo` exemption, the one party
    /// [`get_score_under_exemption`](Self::get_score_under_exemption) serves.
    ///
    /// # Errors
    /// - [`Error::NotInitialized`] if the contract has no admin yet.
    /// - [`Error::InsufficientAdminSigners`] unless `admin_signers` holds at
    ///   least two distinct admin-set members (always the case in
    ///   single-admin mode).
    /// - [`Error::InvalidCoolOffExemptionExpiry`] if `expires_at` is not in
    ///   the future or exceeds `MAX_COOL_OFF_EXEMPTION_SECS` from now.
    /// - [`Error::CoolOffExemptionAlreadyActive`] if an unexpired record
    ///   already exists for `(wallet, mechanism)`.
    pub fn grant_cool_off_exemption(
        env: Env,
        admin_signers: Vec<Address>,
        wallet: Address,
        mechanism: ExemptMechanism,
        governance_ref: BytesN<32>,
        expires_at: u64,
        disclose_to: Option<Address>,
    ) -> Result<(), Error> {
        if !storage::has_admin(&env) {
            return Err(Error::NotInitialized);
        }
        Self::require_admin_auth(&env, &admin_signers)?;
        let approvers = Self::two_distinct_admins(&env, &admin_signers)?;

        let now = env.ledger().timestamp();
        if expires_at <= now || expires_at - now > constants::MAX_COOL_OFF_EXEMPTION_SECS {
            return Err(Error::InvalidCoolOffExemptionExpiry);
        }
        if storage::active_cool_off_exemption(&env, &wallet, mechanism).is_some() {
            return Err(Error::CoolOffExemptionAlreadyActive);
        }

        let exemption = CoolOffExemption {
            mechanism,
            governance_ref: governance_ref.clone(),
            approvers,
            granted_at: now,
            expires_at,
            disclose_to,
        };
        storage::set_cool_off_exemption(&env, &wallet, &exemption);
        events::cool_off_exemption_granted(
            &env,
            &wallet,
            mechanism as u32,
            &governance_ref,
            expires_at,
        );
        Ok(())
    }

    /// Governance: ends `wallet`'s `mechanism` exemption immediately rather
    /// than waiting for it to lapse. Revocation only ever restores normal
    /// behaviour, so ordinary admin authorisation suffices.
    ///
    /// # Errors
    /// - [`Error::NotInitialized`] if the contract has no admin yet.
    /// - [`Error::CoolOffExemptionNotFound`] if no record exists.
    pub fn revoke_cool_off_exemption(
        env: Env,
        admin_signers: Vec<Address>,
        wallet: Address,
        mechanism: ExemptMechanism,
    ) -> Result<(), Error> {
        if !storage::has_admin(&env) {
            return Err(Error::NotInitialized);
        }
        Self::require_admin_auth(&env, &admin_signers)?;
        if storage::get_cool_off_exemption(&env, &wallet, mechanism).is_none() {
            return Err(Error::CoolOffExemptionNotFound);
        }
        storage::remove_cool_off_exemption(&env, &wallet, mechanism);
        events::cool_off_exemption_revoked(
            &env,
            &wallet,
            mechanism as u32,
            &admin_signers.get(0).unwrap_or_else(|| storage::get_admin(&env)),
        );
        Ok(())
    }

    /// Returns `wallet`'s unexpired `mechanism` exemption, or `None`.
    ///
    /// Restricted: `caller` must authorise and be the stored admin, an
    /// admin-set member, or the record's `disclose_to` party. Anyone else
    /// gets [`Error::Unauthorized`] whether or not a record exists, so the
    /// call cannot be used to probe for exemptions. Lapsed records read as
    /// `None`. Never extends TTL.
    pub fn get_cool_off_exemption(
        env: Env,
        caller: Address,
        wallet: Address,
        mechanism: ExemptMechanism,
    ) -> Result<Option<CoolOffExemption>, Error> {
        caller.require_auth();
        let active = storage::active_cool_off_exemption(&env, &wallet, mechanism);
        let is_admin = storage::has_admin(&env)
            && (storage::get_admin(&env) == caller
                || storage::get_admin_set(&env).contains(&caller));
        let is_scoped = active.as_ref().and_then(|e| e.disclose_to.clone()) == Some(caller);
        if !is_admin && !is_scoped {
            return Err(Error::Unauthorized);
        }
        Ok(active)
    }

    /// Scoped read for an embargoed wallet under an `Embargo` exemption.
    ///
    /// When `caller` authorises and is the `disclose_to` party of an
    /// unexpired `Embargo` exemption on `wallet`, returns the wallet's stored
    /// score for `asset_pair` despite the embargo (TTL-neutral, no
    /// delegation). For **every other caller, or once the exemption has
    /// lapsed**, the result is exactly that of
    /// [`get_score`](Self::get_score) — including `Err(ScoreEmbargoed)` — so
    /// the existence of an exemption is not observable through this call.
    pub fn get_score_under_exemption(
        env: Env,
        caller: Address,
        wallet: Address,
        asset_pair: Symbol,
    ) -> Result<RiskScore, Error> {
        caller.require_auth();
        let scoped = storage::active_cool_off_exemption(&env, &wallet, ExemptMechanism::Embargo)
            .and_then(|e| e.disclose_to)
            == Some(caller);
        if !scoped {
            return Self::get_score(env, wallet, asset_pair);
        }
        Self::ensure_asset_pair_bounded(&env, &asset_pair)?;
        storage::peek_score(&env, &wallet, &asset_pair).ok_or(Error::ScoreNotFound)
    }
}

impl LedgerLensScoreContract {
    /// `true` while `wallet` holds an unexpired exemption from `mechanism`.
    /// The only hook the enforcement paths in `lib.rs` consult.
    pub(crate) fn cool_off_exempt(env: &Env, wallet: &Address, mechanism: ExemptMechanism) -> bool {
        storage::active_cool_off_exemption(env, wallet, mechanism).is_some()
    }

    /// Two-person rule for grants: returns the distinct admin-set members in
    /// `admin_signers` (already `require_auth`ed by `require_admin_auth`),
    /// or `InsufficientAdminSigners` if there are fewer than two.
    fn two_distinct_admins(env: &Env, admin_signers: &Vec<Address>) -> Result<Vec<Address>, Error> {
        let admin_set = storage::get_admin_set(env);
        let mut distinct: Vec<Address> = Vec::new(env);
        for signer in admin_signers.iter() {
            if admin_set.contains(&signer) && !distinct.contains(&signer) {
                distinct.push_back(signer);
            }
        }
        if distinct.len() < 2 {
            return Err(Error::InsufficientAdminSigners);
        }
        Ok(distinct)
    }
}
