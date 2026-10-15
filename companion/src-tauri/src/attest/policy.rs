//! Verdict policy: GENUINE / DEVELOPMENT / FAIL, from a verified chain plus the phone's answer.
//! Pure functions over parsed values; unit-tested with real Google chains and synthetic ones.
//! The rules and why are in vault-os/docs/device-attestation.md ("Verdict policy").

use super::chain::ChainInfo;
use super::keydesc::{self, BootState, SecurityLevel};
use super::revocation;
use serde::{Deserialize, Serialize};

const POLICY_JSON: &str = include_str!("../../attestation-policy.json");

#[derive(Debug, Clone)]
pub struct Policy {
    pub package: String,
    pub release_signers: Vec<Vec<u8>>,
    pub development_signers: Vec<Vec<u8>>,
    pub avb_keys: Vec<Vec<u8>>,
    pub min_os_patch_level: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PolicyFile {
    #[serde(rename = "_comment")]
    _comment: Vec<String>,
    package: String,
    release_signer_sha256: Vec<String>,
    development_signer_sha256: Vec<String>,
    avb_key_sha256: Vec<String>,
    min_os_patch_level: u64,
}

fn digests(list: &[String], what: &str) -> Result<Vec<Vec<u8>>, String> {
    list.iter()
        .map(|h| {
            if h.len() != 64 || !h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err(format!("attestation policy: {what} entry must be 64 lowercase hex characters"));
            }
            hex::decode(h).map_err(|e| e.to_string())
        })
        .collect()
}

impl Policy {
    pub fn parse(json: &str) -> Result<Policy, String> {
        let f: PolicyFile = serde_json::from_str(json).map_err(|e| format!("attestation policy: {e}"))?;
        if f.package.is_empty() {
            return Err("attestation policy: package is empty".into());
        }
        if !(201_601..=209_912).contains(&f.min_os_patch_level) {
            return Err("attestation policy: minOsPatchLevel must be YYYYMM".into());
        }
        let p = Policy {
            package: f.package,
            release_signers: digests(&f.release_signer_sha256, "releaseSignerSha256")?,
            development_signers: digests(&f.development_signer_sha256, "developmentSignerSha256")?,
            avb_keys: digests(&f.avb_key_sha256, "avbKeySha256")?,
            min_os_patch_level: f.min_os_patch_level,
        };
        if p.release_signers.iter().any(|r| p.development_signers.contains(r)) {
            return Err("attestation policy: a signer cannot be both release and development".into());
        }
        Ok(p)
    }
    /// The policy compiled into this build.
    pub fn builtin() -> Policy {
        Policy::parse(POLICY_JSON).expect("attestation-policy.json is checked by a unit test")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Genuine,
    Development,
    Fail,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Details {
    pub phone_security_level: String,
    pub attestation_security_level: String,
    pub keymint_security_level: String,
    pub attestation_version: u64,
    pub keymint_version: u64,
    pub device_locked: Option<bool>,
    pub verified_boot_state: Option<String>,
    pub verified_boot_key: Option<String>,
    /// The verified boot key matches a pinned Phone Vault AVB key.
    pub verified_boot_key_known: bool,
    pub verified_boot_hash: Option<String>,
    pub os_version: Option<String>,
    pub os_patch_level: Option<String>,
    pub vendor_patch_level: Option<String>,
    pub boot_patch_level: Option<String>,
    pub app_package: Option<String>,
    pub app_version: Option<u64>,
    pub app_signer: Option<String>,
    /// "release" | "development" | "unknown"
    pub app_signer_kind: String,
    pub root: String,
    pub provisioning: String,
    pub chain_length: usize,
    pub revocation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Assessment {
    pub verdict: Verdict,
    pub headline: String,
    /// Why it FAILED (any entry blocks pairing and sending).
    pub problems: Vec<String>,
    /// Why it is DEVELOPMENT rather than GENUINE.
    pub cautions: Vec<String>,
    /// Informational.
    pub notes: Vec<String>,
    pub details: Option<Details>,
}

/// What the phone said, after the transport-level checks in `mod.rs`.
pub struct Evidence<'a> {
    pub chain: &'a ChainInfo,
    pub phone_level: SecurityLevel,
    /// The challenge this companion generated for this request.
    pub challenge: &'a [u8],
    /// The attested key's signature over the binding message verified.
    pub binding_ok: bool,
    pub revocation: &'a revocation::Status,
}

pub const UNLOCKED_HEADLINE: &str = "Development firmware: bootloader unlocked, not safe for real funds";
pub const UNLOCKED_PROBLEM: &str = "The phone's bootloader is unlocked, so its software can be replaced without anyone noticing. Accept it only for a phone you flashed yourself: Settings → Device → Developer mode.";

pub fn fail(problem: impl Into<String>) -> Assessment {
    let p = problem.into();
    Assessment {
        verdict: Verdict::Fail,
        headline: "Not genuine: this phone failed the genuine check".into(),
        problems: vec![p],
        cautions: vec![],
        notes: vec![],
        details: None,
    }
}

fn short(b: &[u8]) -> String {
    let h = hex::encode(b);
    if h.len() > 16 {
        format!("{}…", &h[..16])
    } else {
        h
    }
}

pub fn evaluate(policy: &Policy, ev: &Evidence, allow_dev: bool) -> Assessment {
    let kd = &ev.chain.description;
    let hw = &kd.hardware;
    let sw = &kd.software;
    let mut problems: Vec<String> = Vec::new();
    let mut cautions: Vec<String> = Vec::new();
    let mut notes: Vec<String> = ev.chain.notes.clone();
    let mut d = Details {
        phone_security_level: ev.phone_level.name().into(),
        attestation_security_level: kd.attestation_security_level.name().into(),
        keymint_security_level: kd.keymint_security_level.name().into(),
        attestation_version: kd.attestation_version,
        keymint_version: kd.keymint_version,
        os_version: hw.os_version.map(keydesc::os_version_text),
        os_patch_level: hw.os_patch_level.map(keydesc::patch_level_text),
        vendor_patch_level: hw.vendor_patch_level.map(keydesc::patch_level_text),
        boot_patch_level: hw.boot_patch_level.map(keydesc::patch_level_text),
        app_signer_kind: "unknown".into(),
        root: ev.chain.root.into(),
        provisioning: format!("{:?}", ev.chain.provisioning).to_lowercase(),
        chain_length: ev.chain.chain_length,
        ..Details::default()
    };

    // freshness: the certificate must answer THIS challenge
    if kd.challenge != ev.challenge {
        problems.push(
            "The genuine-check answer is for a different challenge than the one this Mac sent (replayed or substituted)."
                .into(),
        );
    }

    // revocation
    match ev.revocation {
        revocation::Status::Checked { revoked, as_of } => {
            let hits: Vec<String> =
                ev.chain.serials.iter().filter_map(|s| revoked.get(s).map(|r| format!("{s} ({r})"))).collect();
            if hits.is_empty() {
                d.revocation = format!("Not revoked (Google status list of {as_of})");
            } else {
                d.revocation = "REVOKED".into();
                problems.push(format!(
                    "Google has revoked a certificate in this phone's genuine-check chain: {}.",
                    hits.join(", ")
                ));
            }
        }
        revocation::Status::Unknown(why) => {
            d.revocation = format!("Unknown ({why})");
            notes.push(format!("Revocation status unknown: {why}. Not a failure, but the check is incomplete."));
        }
    }

    // where the key lives
    let level = kd.attestation_security_level;
    if level == SecurityLevel::Software || kd.keymint_security_level == SecurityLevel::Software {
        problems.push("The key is held by software, not by secure hardware.".into());
    } else if level != kd.keymint_security_level {
        problems.push("The genuine-check answer reports two different security levels.".into());
    } else if ev.phone_level != level {
        problems.push(format!(
            "The phone said its key is in {}, but its genuine-check answer says {}.",
            ev.phone_level.name(),
            level.name()
        ));
    } else if level == SecurityLevel::StrongBox && !ev.chain.chain_names_strongbox {
        problems.push(
            "The genuine-check answer claims StrongBox, but its certificate chain is not a StrongBox chain.".into(),
        );
    } else if level != SecurityLevel::StrongBox && ev.chain.chain_names_strongbox {
        problems
            .push("The certificate chain is a StrongBox chain, but the key claims a different security level.".into());
    } else if level == SecurityLevel::TrustedEnvironment {
        cautions.push(
            "The key is held by the phone's TEE, not the Titan M security chip (StrongBox was unavailable).".into(),
        );
    }
    if hw.origin != Some(keydesc::ORIGIN_GENERATED) {
        problems.push("The key in the genuine check was not generated inside the secure hardware.".into());
    }
    if ev.chain.leaf_p256_point.is_none() {
        problems.push("The key in the genuine check is not a P-256 key.".into());
    } else if !ev.binding_ok {
        problems
            .push("The phone's statement of its wallet address is not signed by the key in the genuine check.".into());
    }

    // which app holds the key
    match &sw.app_id {
        None => problems.push("The genuine-check answer does not name the app that holds the key.".into()),
        Some(app) => {
            d.app_package = Some(app.packages.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", "));
            d.app_version = app.packages.first().map(|p| p.version);
            if app.packages.len() != 1 || app.packages[0].name != policy.package {
                problems.push(format!(
                    "The key in the genuine check belongs to {}, not the Phone Vault app ({}).",
                    d.app_package.as_deref().filter(|s| !s.is_empty()).unwrap_or("no package"),
                    policy.package
                ));
            }
            if app.signature_digests.len() != 1 {
                problems.push(format!(
                    "The app has {} signing certificates; Phone Vault has exactly one.",
                    app.signature_digests.len()
                ));
            } else {
                let digest = &app.signature_digests[0];
                d.app_signer = Some(hex::encode(digest));
                if policy.release_signers.contains(digest) {
                    d.app_signer_kind = "release".into();
                } else if policy.development_signers.contains(digest) {
                    d.app_signer_kind = "development".into();
                    if allow_dev {
                        cautions.push("The Phone Vault app is signed with the development key (Developer mode is on on this Mac).".into());
                    } else {
                        problems.push("The Phone Vault app is signed with the development key, not the release key. Turn on Developer mode in Settings → Device only for a development phone.".into());
                    }
                } else {
                    problems.push(format!("The app on this phone is signed by an unknown key ({}): it is not the Phone Vault app from us.", short(digest)));
                }
            }
        }
    }

    // what booted
    match &hw.root_of_trust {
        None => problems.push("The genuine-check answer has no hardware root of trust (boot state).".into()),
        Some(rot) => {
            let key_known = policy.avb_keys.contains(&rot.verified_boot_key);
            d.device_locked = Some(rot.device_locked);
            d.verified_boot_state = Some(rot.verified_boot_state.describe().into());
            d.verified_boot_key = Some(hex::encode(&rot.verified_boot_key));
            d.verified_boot_key_known = key_known;
            d.verified_boot_hash = rot.verified_boot_hash.as_ref().map(hex::encode);
            let pinned_note = if policy.avb_keys.is_empty() {
                " (this companion build has no Phone Vault release boot key pinned yet)"
            } else {
                ""
            };
            match (rot.device_locked, rot.verified_boot_state) {
                (_, BootState::Failed) => problems.push("Verified boot reports FAILED (red).".into()),
                (true, BootState::Verified) | (true, BootState::SelfSigned) if key_known => {
                    match hw.os_patch_level {
                        None => problems.push("The genuine-check answer has no OS patch level.".into()),
                        Some(p) if keydesc::patch_month(p) < policy.min_os_patch_level => problems.push(format!(
                            "The firmware's security patch level {} is older than the oldest this Mac accepts ({}).",
                            keydesc::patch_level_text(p), keydesc::patch_level_text(policy.min_os_patch_level))),
                        Some(_) => {}
                    }
                }
                (true, BootState::Verified) => problems.push(format!("The phone is locked to its maker's stock software, not Phone Vault firmware{pinned_note}.")),
                (true, BootState::SelfSigned) => problems.push(format!("The phone boots firmware signed by a key that is not Phone Vault's (verified boot key {}){pinned_note}.", short(&rot.verified_boot_key))),
                (true, BootState::Unverified) => problems.push("The phone reports a locked bootloader with unverified (orange) boot, which is inconsistent.".into()),
                // An unlocked bootloader lets anything above the security chip be replaced: never
                // acceptable for a phone someone else set up. Only Developer mode (a typed
                // confirmation in Settings → Device, kept on this Mac) accepts it, as DEVELOPMENT.
                (false, _) if allow_dev => cautions.push(UNLOCKED_HEADLINE.to_string()),
                (false, _) => problems.push(UNLOCKED_PROBLEM.to_string()),
            }
            if !rot.device_locked {
                if let Some(p) = hw.os_patch_level {
                    if keydesc::patch_month(p) < policy.min_os_patch_level {
                        notes.push(format!(
                            "Security patch level {} is older than {}.",
                            keydesc::patch_level_text(p),
                            keydesc::patch_level_text(policy.min_os_patch_level)
                        ));
                    }
                }
            }
        }
    }

    let (verdict, headline) = if !problems.is_empty() {
        (Verdict::Fail, "Not genuine: this phone failed the genuine check".to_string())
    } else if !cautions.is_empty() {
        let unlocked = cautions.iter().any(|c| c == UNLOCKED_HEADLINE);
        (
            Verdict::Development,
            if unlocked { UNLOCKED_HEADLINE.into() } else { "Development device: not safe for real funds".into() },
        )
    } else {
        (
            Verdict::Genuine,
            "Genuine Phone Vault: locked Phone Vault firmware, Phone Vault app, keys in the Titan M".into(),
        )
    };
    Assessment { verdict, headline, problems, cautions, notes, details: Some(d) }
}
