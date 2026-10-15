//! Attestation tests.
//!
//! Real chains: testdata/*.pem are attestation certificate chains captured from physical devices
//! and published by Google in https://github.com/android/keyattestation (testdata/, Apache-2.0,
//! commit 3f550f94a9e3c010dda7cdcad8bca764cd76d4f4), with the library's expected parse in the
//! matching *.json. blueline = Pixel 3 (same SoC and Titan M as our crosshatch / Pixel 3 XL),
//! tegu = Pixel 9a (new EC root), caiman = Pixel 9 Pro (remote provisioning, old RSA root).
//!
//! Synthetic chains: built in memory per test run with rcgen under a TEST-ONLY root key that is
//! generated on the fly and never written anywhere. They exercise the Phone Vault-specific paths
//! a Google sample cannot (our package, our binding signature, a locked phone with our boot key).

use super::chain::{self, Provisioning, TrustedRoot};
use super::keydesc::{self, BootState, SecurityLevel};
use super::policy::{self, Policy, Verdict};
use super::revocation::Status;
use super::*;
use base64::engine::general_purpose::STANDARD as B64;
use std::collections::HashMap;

// ------------------------------------------------------------------ helpers

fn pem_chain(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let body = block.split("-----END CERTIFICATE-----").next().unwrap();
        let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        out.push(B64.decode(b64).unwrap());
    }
    out
}

const BLUELINE_SB: &str = include_str!("testdata/blueline_sdk28_SB_RSA_NONE.pem");
const BLUELINE_SB_JSON: &str = include_str!("testdata/blueline_sdk28_SB_RSA_NONE.json");
const BLUELINE_TEE: &str = include_str!("testdata/blueline_sdk28_TEE_EC_NONE.pem");
const BLUELINE_TEE_JSON: &str = include_str!("testdata/blueline_sdk28_TEE_EC_NONE.json");
const TEGU_SB: &str = include_str!("testdata/tegu_sdk36_SB_EC_2026_ROOT.pem");
const TEGU_SB_JSON: &str = include_str!("testdata/tegu_sdk36_SB_EC_2026_ROOT.json");
const CAIMAN_SB: &str = include_str!("testdata/caiman_sdk36_SB_EC_RKP.pem");
const CAIMAN_SB_JSON: &str = include_str!("testdata/caiman_sdk36_SB_EC_RKP.json");
const INVALID_ROT: &str = include_str!("testdata/invalid_malformed_rot_device_locked.pem");
const INVALID_ORDER: &str = include_str!("testdata/invalid_tags_not_in_ascending_order.pem");
const GOOGLE_ROOTS_JSON: &str = include_str!("testdata/google_roots.json");
const VECTORS: &str = include_str!("../../../../app/src/test/resources/attestation-vectors.json");

/// 2026-10-10 00:00 UTC, "today" for the factory (Pixel 3) chains.
const NOW: i64 = 1_791_590_400;
/// Inside the short-lived remotely provisioned certificates' windows.
const TEGU_NOW: i64 = 1_772_000_000; // 2026-02-25
const CAIMAN_NOW: i64 = 1_758_950_000; // 2025-09-27

fn roots() -> Vec<TrustedRoot> {
    chain::google_roots()
}
fn b64(s: &str) -> Vec<u8> {
    B64.decode(s).unwrap()
}
fn unchecked() -> Status {
    Status::Checked { revoked: HashMap::new(), as_of: "2026-10-10".into() }
}

// ------------------------------------------------------------------ roots

#[test]
fn embedded_root_keys_are_googles_published_roots() {
    let pems: Vec<String> = serde_json::from_str(GOOGLE_ROOTS_JSON).unwrap();
    assert_eq!(pems.len(), 2, "android.googleapis.com/attestation/root lists two roots");
    let r = roots();
    for (pem, root) in pems.iter().zip(r.iter()) {
        let der = &pem_chain(pem)[0];
        let (_, cert) = x509_parser::parse_x509_certificate(der).unwrap();
        assert_eq!(cert.public_key().raw, root.spki.as_slice(), "{}", root.name);
    }
    use ring::digest::{digest, SHA256};
    assert_eq!(
        hex::encode(digest(&SHA256, &r[0].spki)),
        "feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae"
    );
    assert_eq!(
        hex::encode(digest(&SHA256, &r[1].spki)),
        "3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec"
    );
}

// ------------------------------------------------------------------ real chains: parse + verify

fn sec(s: &str) -> SecurityLevel {
    match s {
        "STRONG_BOX" => SecurityLevel::StrongBox,
        "TRUSTED_ENVIRONMENT" => SecurityLevel::TrustedEnvironment,
        _ => SecurityLevel::Software,
    }
}

/// Every field we rely on matches Google's own parse of the same certificate.
fn check_against_reference(pem: &str, json: &str, now: i64) -> chain::ChainInfo {
    let info = chain::verify(&pem_chain(pem), &roots(), now).unwrap_or_else(|e| panic!("chain should verify: {e}"));
    let j: serde_json::Value = serde_json::from_str(json).unwrap();
    let kd = &info.description;
    let num = |v: &serde_json::Value| v.as_str().unwrap().parse::<u64>().unwrap();
    assert_eq!(kd.attestation_version, num(&j["attestationVersion"]));
    assert_eq!(kd.keymint_version, num(&j["keyMintVersion"]));
    assert_eq!(kd.attestation_security_level, sec(j["attestationSecurityLevel"].as_str().unwrap()));
    assert_eq!(kd.keymint_security_level, sec(j["keyMintSecurityLevel"].as_str().unwrap()));
    assert_eq!(kd.challenge, b64(j["attestationChallenge"].as_str().unwrap()));
    let app = kd.software.app_id.as_ref().expect("attestationApplicationId");
    let jp = &j["softwareEnforced"]["attestationApplicationId"];
    assert_eq!(app.packages.len(), jp["packages"].as_array().unwrap().len());
    assert_eq!(app.packages[0].name, jp["packages"][0]["name"].as_str().unwrap());
    assert_eq!(app.packages[0].version, num(&jp["packages"][0]["version"]));
    assert_eq!(
        app.signature_digests,
        jp["signatures"].as_array().unwrap().iter().map(|s| b64(s.as_str().unwrap())).collect::<Vec<_>>()
    );
    assert_eq!(kd.software.creation_datetime, Some(num(&j["softwareEnforced"]["creationDateTime"])));
    let h = &j["hardwareEnforced"];
    let rot = kd.hardware.root_of_trust.as_ref().expect("rootOfTrust");
    assert_eq!(rot.verified_boot_key, b64(h["rootOfTrust"]["verifiedBootKey"].as_str().unwrap()));
    assert_eq!(rot.device_locked, h["rootOfTrust"]["deviceLocked"].as_bool().unwrap());
    let state = match h["rootOfTrust"]["verifiedBootState"].as_str().unwrap() {
        "VERIFIED" => BootState::Verified,
        "SELF_SIGNED" => BootState::SelfSigned,
        "UNVERIFIED" => BootState::Unverified,
        _ => BootState::Failed,
    };
    assert_eq!(rot.verified_boot_state, state);
    assert_eq!(
        rot.verified_boot_hash.as_deref(),
        Some(b64(h["rootOfTrust"]["verifiedBootHash"].as_str().unwrap()).as_slice())
    );
    assert_eq!(kd.hardware.os_version, Some(num(&h["osVersion"])));
    assert_eq!(kd.hardware.os_patch_level, Some(num(&h["osPatchLevel"])));
    assert_eq!(kd.hardware.vendor_patch_level, Some(num(&h["vendorPatchLevel"])));
    assert_eq!(kd.hardware.boot_patch_level, Some(num(&h["bootPatchLevel"])));
    assert_eq!(kd.hardware.origin, Some(keydesc::ORIGIN_GENERATED));
    assert_eq!(kd.hardware.no_auth_required, h["noAuthRequired"].as_bool().unwrap_or(false));
    assert_eq!(kd.hardware.key_size, Some(num(&h["keySize"])));
    assert_eq!(kd.hardware.algorithm, Some(num(&h["algorithms"])));
    assert_eq!(kd.hardware.purposes, h["purposes"].as_array().unwrap().iter().map(num).collect::<Vec<_>>());
    info
}

#[test]
fn pixel3_strongbox_chain_verifies_to_the_rsa_root_today() {
    // Pixel 3 factory StrongBox chain; its 2016 root certificate expired 2026-05-24, the key is
    // still the pinned anchor and the intermediates are valid until 2028.
    let info = check_against_reference(BLUELINE_SB, BLUELINE_SB_JSON, NOW);
    assert_eq!(info.root, "Google Hardware Attestation Root (RSA)");
    assert_eq!(info.provisioning, Provisioning::Factory);
    assert!(info.chain_names_strongbox, "factory StrongBox chains carry title=StrongBox");
    assert!(info.leaf_p256_point.is_none(), "this sample attests an RSA key");
    assert_eq!(info.chain_length, 4);
    assert_eq!(info.serials[3], "e8fa196314d2fa18", "root serial in the status list's format");
    assert_eq!(info.serials[1], "17102468407102977850", "hex digits that look decimal, like many status-list keys");
    assert!(info.notes.is_empty(), "{:?}", info.notes);
    let rot = info.description.hardware.root_of_trust.as_ref().unwrap();
    assert!(
        !rot.device_locked && rot.verified_boot_state == BootState::Unverified,
        "an unlocked Pixel 3, like our dev phones"
    );
}

#[test]
fn pixel3_tee_chain_is_not_a_strongbox_chain() {
    let info = check_against_reference(BLUELINE_TEE, BLUELINE_TEE_JSON, NOW);
    assert!(!info.chain_names_strongbox);
    assert_eq!(info.description.attestation_security_level, SecurityLevel::TrustedEnvironment);
    assert!(info.leaf_p256_point.is_some());
}

#[test]
fn new_ec_root_and_remote_provisioning_verify() {
    let info = check_against_reference(TEGU_SB, TEGU_SB_JSON, TEGU_NOW);
    assert_eq!(info.root, "Google Key Attestation CA1 (EC, 2026)");
    assert_eq!(info.provisioning, Provisioning::Remote);
    assert!(info.chain_names_strongbox, "RKP StrongBox attestation certificates carry O=StrongBox");
    let info = check_against_reference(CAIMAN_SB, CAIMAN_SB_JSON, CAIMAN_NOW);
    assert_eq!(info.root, "Google Hardware Attestation Root (RSA)");
    assert_eq!(info.provisioning, Provisioning::Remote);
}

#[test]
fn validity_is_enforced_except_for_expired_factory_keys() {
    // remotely provisioned certificates live days; expired is a failure
    let e = chain::verify(&pem_chain(CAIMAN_SB), &roots(), NOW).unwrap_err();
    assert!(e.contains("expired"), "{e}");
    // factory intermediates past their date: tolerated (Google's verifier does the same), noted
    let info = chain::verify(&pem_chain(BLUELINE_SB), &roots(), 1_893_456_000 /* 2030-01-01 */).unwrap();
    assert!(info.notes.iter().any(|n| n.contains("expired") && n.contains("2028")), "{:?}", info.notes);
    // not yet valid is never tolerated
    let e = chain::verify(&pem_chain(BLUELINE_SB), &roots(), 1_514_764_800 /* 2018-01-01 */).unwrap_err();
    assert!(e.contains("not valid until"), "{e}");
}

#[test]
fn unknown_root_tampering_and_broken_links_fail() {
    let chain_ = pem_chain(BLUELINE_SB);
    // only the EC root trusted → the RSA-rooted chain has no anchor
    let ec_only = vec![roots().remove(1)];
    assert!(chain::verify(&chain_, &ec_only, NOW).unwrap_err().contains("Google hardware attestation root"));
    // a flipped bit in the leaf's signature
    let mut bad = chain_.clone();
    let n = bad[0].len();
    bad[0][n - 5] ^= 0x01;
    assert!(chain::verify(&bad, &roots(), NOW).unwrap_err().contains("signature does not verify"));
    // a flipped byte inside the attestation extension (the challenge "challenge" → "chbllenge")
    let mut bad = chain_.clone();
    let pos = bad[0].windows(9).position(|w| w == b"challenge").unwrap();
    bad[0][pos + 2] = b'b';
    assert!(chain::verify(&bad, &roots(), NOW).is_err());
    // an intermediate removed → name chaining breaks
    let mut short = chain_.clone();
    short.remove(1);
    assert!(chain::verify(&short, &roots(), NOW).unwrap_err().contains("issuer"));
    // the root alone, garbage, and trailing bytes
    assert!(chain::verify(&chain_[3..], &roots(), NOW).is_err());
    assert!(chain::verify(&[vec![0x30, 0x00], chain_[3].clone()], &roots(), NOW).is_err());
    let mut trailing = chain_.clone();
    trailing[0].push(0);
    assert!(chain::verify(&trailing, &roots(), NOW).unwrap_err().contains("trailing"));
}

#[test]
fn googles_invalid_samples_are_refused() {
    // deviceLocked encoded as something other than a DER boolean
    let e = chain::verify(&pem_chain(INVALID_ROT), &roots(), NOW).unwrap_err();
    assert!(e.contains("deviceLocked is not a DER boolean"), "{e}");
    // AuthorizationList tags out of order. Google's sample was edited without re-signing, so the
    // chain already fails on its signature; the parser must refuse the extension on its own too.
    let ders = pem_chain(INVALID_ORDER);
    assert!(chain::verify(&ders, &roots(), NOW).is_err());
    let (_, leaf) = x509_parser::parse_x509_certificate(&ders[0]).unwrap();
    let ext = leaf.extensions().iter().find(|e| e.oid.to_id_string() == keydesc::OID_KEY_DESCRIPTION).unwrap();
    let e = keydesc::parse(ext.value).unwrap_err();
    assert!(e.contains("ascending"), "{e}");
}

// ------------------------------------------------------------------ policy on real chains

fn policy_for(info: &chain::ChainInfo, release: bool) -> Policy {
    let app = info.description.software.app_id.as_ref().unwrap();
    let rot = info.description.hardware.root_of_trust.as_ref().unwrap();
    Policy {
        package: app.packages[0].name.clone(),
        release_signers: if release { app.signature_digests.clone() } else { vec![] },
        development_signers: if release { vec![] } else { app.signature_digests.clone() },
        avb_keys: vec![rot.verified_boot_key.clone()],
        min_os_patch_level: 201_801,
    }
}

fn evaluate(
    info: &chain::ChainInfo,
    policy: &Policy,
    level: SecurityLevel,
    challenge: &[u8],
    status: &Status,
    allow_dev: bool,
) -> policy::Assessment {
    let ev = policy::Evidence { chain: info, phone_level: level, challenge, binding_ok: true, revocation: status };
    policy::evaluate(policy, &ev, allow_dev)
}

#[test]
fn locked_strongbox_phone_with_pinned_app_and_boot_key_is_genuine() {
    let info = chain::verify(&pem_chain(TEGU_SB), &roots(), TEGU_NOW).unwrap();
    let challenge = info.description.challenge.clone();
    let p = policy_for(&info, true);
    let a = evaluate(&info, &p, SecurityLevel::StrongBox, &challenge, &unchecked(), false);
    assert_eq!(a.verdict, Verdict::Genuine, "{a:?}");
    let d = a.details.unwrap();
    assert_eq!(d.app_signer_kind, "release");
    assert!(d.verified_boot_key_known);
    assert_eq!(d.os_patch_level.as_deref(), Some("2026-02"));
    assert_eq!(d.os_version.as_deref(), Some("16.0.0"));
    assert!(d.revocation.starts_with("Not revoked"));

    // revocation unknown: still genuine, said plainly
    let a = evaluate(&info, &p, SecurityLevel::StrongBox, &challenge, &Status::Unknown("offline".into()), false);
    assert_eq!(a.verdict, Verdict::Genuine);
    assert!(a.notes.iter().any(|n| n.contains("Revocation status unknown")));
}

#[test]
fn every_fail_rule_fires_on_an_otherwise_genuine_attestation() {
    let info = chain::verify(&pem_chain(TEGU_SB), &roots(), TEGU_NOW).unwrap();
    let challenge = info.description.challenge.clone();
    let good = policy_for(&info, true);
    let fails = |a: policy::Assessment, needle: &str| {
        assert_eq!(a.verdict, Verdict::Fail, "{needle}: {a:?}");
        assert!(a.problems.iter().any(|p| p.contains(needle)), "expected '{needle}' in {:?}", a.problems);
    };
    // challenge mismatch (replay)
    fails(
        evaluate(&info, &good, SecurityLevel::StrongBox, b"another challenge", &unchecked(), false),
        "different challenge",
    );
    // the phone claims a different level than the chain
    fails(
        evaluate(&info, &good, SecurityLevel::TrustedEnvironment, &challenge, &unchecked(), false),
        "its genuine-check answer says StrongBox",
    );
    // revoked intermediate
    let mut revoked = HashMap::new();
    revoked.insert(info.serials[1].clone(), "KEY_COMPROMISE".to_string());
    fails(
        evaluate(
            &info,
            &good,
            SecurityLevel::StrongBox,
            &challenge,
            &Status::Checked { revoked, as_of: "x".into() },
            false,
        ),
        "revoked",
    );
    // wrong package
    let mut p = good.clone();
    p.package = "dev.phonevault.signer".into();
    fails(evaluate(&info, &p, SecurityLevel::StrongBox, &challenge, &unchecked(), false), "not the Phone Vault app");
    // unknown app signer
    let mut p = good.clone();
    p.release_signers = vec![vec![7u8; 32]];
    fails(evaluate(&info, &p, SecurityLevel::StrongBox, &challenge, &unchecked(), false), "unknown key");
    // development signer without Developer mode
    let p = policy_for(&info, false);
    fails(evaluate(&info, &p, SecurityLevel::StrongBox, &challenge, &unchecked(), false), "development key");
    // locked + green, but the boot key is not ours → stock firmware
    let mut p = good.clone();
    p.avb_keys = vec![];
    fails(evaluate(&info, &p, SecurityLevel::StrongBox, &challenge, &unchecked(), false), "stock software");
    // patch level too old
    let mut p = good.clone();
    p.min_os_patch_level = 202_603;
    fails(evaluate(&info, &p, SecurityLevel::StrongBox, &challenge, &unchecked(), false), "patch level");
    // address binding signature did not verify
    let ev = policy::Evidence {
        chain: &info,
        phone_level: SecurityLevel::StrongBox,
        challenge: &challenge,
        binding_ok: false,
        revocation: &unchecked(),
    };
    fails(policy::evaluate(&good, &ev, false), "not signed by the key in the genuine check");
    // StrongBox claimed, but the chain is not a StrongBox chain
    let mut forged = info.clone();
    forged.chain_names_strongbox = false;
    fails(evaluate(&forged, &good, SecurityLevel::StrongBox, &challenge, &unchecked(), false), "not a StrongBox chain");
    // software attestation
    let mut soft = info.clone();
    soft.description.attestation_security_level = SecurityLevel::Software;
    soft.description.keymint_security_level = SecurityLevel::Software;
    fails(evaluate(&soft, &good, SecurityLevel::StrongBox, &challenge, &unchecked(), false), "software");
    // imported (not generated) key
    let mut imported = info.clone();
    imported.description.hardware.origin = Some(2);
    fails(evaluate(&imported, &good, SecurityLevel::StrongBox, &challenge, &unchecked(), false), "not generated");
    // yellow boot with somebody else's key
    let mut yellow = info.clone();
    yellow.description.hardware.root_of_trust.as_mut().unwrap().verified_boot_state = BootState::SelfSigned;
    let mut p = good.clone();
    p.avb_keys = vec![vec![9u8; 32]];
    fails(evaluate(&yellow, &p, SecurityLevel::StrongBox, &challenge, &unchecked(), false), "not Phone Vault's");
    // ... and yellow WITH our key is genuine (custom-key relock on a Pixel boots yellow)
    let a = evaluate(&yellow, &good, SecurityLevel::StrongBox, &challenge, &unchecked(), false);
    assert_eq!(a.verdict, Verdict::Genuine, "{a:?}");
    // red
    let mut red = info.clone();
    red.description.hardware.root_of_trust.as_mut().unwrap().verified_boot_state = BootState::Failed;
    fails(evaluate(&red, &good, SecurityLevel::StrongBox, &challenge, &unchecked(), false), "FAILED");
    // the policy compiled into the app refuses Google's sample outright (not our package)
    fails(
        evaluate(&info, &Policy::builtin(), SecurityLevel::StrongBox, &challenge, &unchecked(), false),
        "not the Phone Vault app",
    );
}

#[test]
fn unlocked_pixel3_is_development_and_says_so() {
    // The Pixel 3 sample is unlocked + orange, exactly like today's dev phones. Its key is RSA, so
    // the binding is exercised separately; here the chain stands in for an EC one.
    let mut info = chain::verify(&pem_chain(BLUELINE_SB), &roots(), NOW).unwrap();
    info.leaf_p256_point = Some(vec![4u8; 65]);
    let challenge = b"challenge".to_vec();
    // release-signed app on an unlocked phone: FAIL without Developer mode (an unlocked bootloader
    // is never accepted from a phone someone else set up) …
    let a = evaluate(&info, &policy_for(&info, true), SecurityLevel::StrongBox, &challenge, &unchecked(), false);
    assert_eq!(a.verdict, Verdict::Fail, "{a:?}");
    assert!(a.problems.iter().any(|p| p == policy::UNLOCKED_PROBLEM), "{:?}", a.problems);
    assert_eq!(a.details.as_ref().unwrap().device_locked, Some(false));
    // … and DEVELOPMENT with it, with the plain headline
    let a = evaluate(&info, &policy_for(&info, true), SecurityLevel::StrongBox, &challenge, &unchecked(), true);
    assert_eq!(a.verdict, Verdict::Development, "{a:?}");
    assert_eq!(a.headline, policy::UNLOCKED_HEADLINE);
    assert_eq!(a.details.as_ref().unwrap().device_locked, Some(false));
    // development-signed app: FAIL without Developer mode, DEVELOPMENT with it
    let p = policy_for(&info, false);
    assert_eq!(evaluate(&info, &p, SecurityLevel::StrongBox, &challenge, &unchecked(), false).verdict, Verdict::Fail);
    let a = evaluate(&info, &p, SecurityLevel::StrongBox, &challenge, &unchecked(), true);
    assert_eq!(a.verdict, Verdict::Development);
    assert_eq!(
        a.headline,
        policy::UNLOCKED_HEADLINE,
        "today's dev phones (Pixel 3 XL: unlocked, dev-signed app) look exactly as before"
    );
    assert!(a.cautions.iter().any(|c| c.contains("development key")));
    assert_eq!(a.details.unwrap().app_signer_kind, "development");
    // old patch level on a dev phone is a note, not a failure
    let mut p2 = policy_for(&info, true);
    p2.min_os_patch_level = 202_501;
    let a = evaluate(&info, &p2, SecurityLevel::StrongBox, &challenge, &unchecked(), true);
    assert_eq!(a.verdict, Verdict::Development);
    assert!(a.notes.iter().any(|n| n.contains("2019-08")), "{:?}", a.notes);
}

#[test]
fn tee_attestation_is_never_genuine() {
    let info = chain::verify(&pem_chain(BLUELINE_TEE), &roots(), NOW).unwrap();
    let challenge = info.description.challenge.clone();
    // (the sample phone is unlocked: Developer mode on, so the TEE caution is what is tested)
    let a =
        evaluate(&info, &policy_for(&info, true), SecurityLevel::TrustedEnvironment, &challenge, &unchecked(), true);
    assert_eq!(a.verdict, Verdict::Development, "{a:?}");
    assert!(a.cautions.iter().any(|c| c.contains("TEE")));
    // and claiming StrongBox for a TEE chain fails
    let a = evaluate(&info, &policy_for(&info, true), SecurityLevel::StrongBox, &challenge, &unchecked(), false);
    assert_eq!(a.verdict, Verdict::Fail);
}

#[test]
fn builtin_policy_parses_and_refuses_bad_files() {
    let p = Policy::builtin();
    assert_eq!(p.package, "dev.phonevault.signer");
    assert!(p.release_signers.is_empty(), "no release key exists yet; pin it at release (ROADMAP.md)");
    assert!(p.avb_keys.is_empty(), "no release AVB key exists yet");
    assert_eq!(
        p.development_signers,
        vec![hex::decode("d8eab12db9f77634d1663d66df9928c184a2c91df03e3ea78abcddd64f114b53").unwrap()],
        "the build host's Android Debug certificate that signs the dev appliance APK"
    );
    assert!(Policy::parse(r#"{"_comment":[],"package":"x","releaseSignerSha256":["AB"],"developmentSignerSha256":[],"avbKeySha256":[],"minOsPatchLevel":202501}"#).is_err());
    assert!(Policy::parse(r#"{"_comment":[],"package":"x","releaseSignerSha256":[],"developmentSignerSha256":[],"avbKeySha256":[],"minOsPatchLevel":202501,"extra":1}"#).is_err());
    let same = "11".repeat(32);
    assert!(Policy::parse(&format!(r#"{{"_comment":[],"package":"x","releaseSignerSha256":["{same}"],"developmentSignerSha256":["{same}"],"avbKeySha256":[],"minOsPatchLevel":202501}}"#)).is_err());
}

// ------------------------------------------------------------------ protocol

#[test]
fn binding_message_matches_the_shared_vectors() {
    let v: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
    assert_eq!(v["domain"].as_str().unwrap().as_bytes(), DOMAIN);
    for t in v["vectors"].as_array().unwrap() {
        let challenge = hex::decode(t["challenge"].as_str().unwrap()).unwrap();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hex::decode(&t["address"].as_str().unwrap()[2..]).unwrap());
        assert_eq!(hex::encode(binding_message(&challenge, &addr)), t["message"].as_str().unwrap(), "{}", t["name"]);
    }
}

#[test]
fn response_schema_is_exact() {
    let req = request("r1", &[1u8; 32]);
    let ok = json!({"id":"r1","status":"ok","version":"1","address":"0x52908400098527886e0f7030069857d2e4169ee7","securityLevel":"StrongBox",
        "certificates": format!("{},{}", B64.encode([0x30u8, 0]), B64.encode([0x30u8, 0])), "signature":"0x3006020101020101"});
    assert!(matches!(parse_response(&req, &ok), Ok(Answer::Attestation(_))));
    let with = |k: &str, v: serde_json::Value| {
        let mut r = ok.clone();
        r[k] = v;
        r
    };
    assert!(parse_response(&req, &with("id", json!("r2"))).is_err(), "wrong id");
    assert!(parse_response(&req, &with("extra", json!("x"))).is_err(), "unknown field");
    assert!(parse_response(&req, &with("version", json!("2"))).is_err());
    assert!(parse_response(&req, &with("securityLevel", json!("Software"))).is_err());
    assert!(
        parse_response(&req, &with("address", json!("0x52908400098527886E0F7030069857D2E4169EE7"))).is_err(),
        "address must be lowercase"
    );
    assert!(parse_response(&req, &with("certificates", json!("AAA="))).is_err(), "one certificate is not a chain");
    assert!(parse_response(&req, &with("certificates", json!("!!,??"))).is_err());
    assert!(parse_response(&req, &with("signature", json!("3006"))).is_err(), "0x required");
    assert!(parse_response(&req, &with("signature", json!(format!("0x{}", "00".repeat(81))))).is_err(), "too long");
    let refused = json!({"id":"r1","status":"error","error":"Request fields do not match schema"});
    assert!(matches!(parse_response(&req, &refused), Ok(Answer::Refused(_))));
}

#[test]
fn transient_refusals_are_errors_and_others_fail() {
    let req = request("r1", &[1u8; 32]);
    let p = Policy::builtin();
    let not_ready =
        json!({"id":"r1","status":"error","error":"Wallet is not ready: unlock and complete the backup check first"});
    assert!(assess(&p, &roots(), NOW, &[1u8; 32], &req, &not_ready, unchecked, false).is_err());
    let old_app = json!({"id":"r1","status":"error","error":"Unsupported method"});
    let r =
        assess(&p, &roots(), NOW, &[1u8; 32], &req, &old_app, || panic!("no revocation fetch for a refusal"), false)
            .unwrap();
    assert_eq!(r.verdict(), Verdict::Fail);
    assert!(r.assessment.problems[0].contains("update the app"));
    let garbage = json!({"id":"r1","status":"ok"});
    assert_eq!(
        assess(&p, &roots(), NOW, &[1u8; 32], &req, &garbage, unchecked, false).unwrap().verdict(),
        Verdict::Fail
    );
}

// ------------------------------------------------------------------ synthetic end-to-end (TEST ROOT)

mod synthetic {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair as _, ECDSA_P256_SHA256_ASN1_SIGNING};

    // --- a tiny DER writer for the KeyDescription
    fn tlv(tag: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = tag.to_vec();
        let n = body.len();
        if n < 0x80 {
            out.push(n as u8);
        } else if n < 0x100 {
            out.extend([0x81, n as u8]);
        } else {
            out.extend([0x82, (n >> 8) as u8, n as u8]);
        }
        out.extend_from_slice(body);
        out
    }
    fn int(v: u64) -> Vec<u8> {
        let mut b: Vec<u8> = v.to_be_bytes().iter().copied().skip_while(|&x| x == 0).collect();
        if b.is_empty() || b[0] & 0x80 != 0 {
            b.insert(0, 0);
        }
        tlv(&[0x02], &b)
    }
    fn enumerated(v: u64) -> Vec<u8> {
        let mut i = int(v);
        i[0] = 0x0a;
        i
    }
    fn octets(b: &[u8]) -> Vec<u8> {
        tlv(&[0x04], b)
    }
    fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
        tlv(&[0x30], &parts.concat())
    }
    fn set(parts: &[Vec<u8>]) -> Vec<u8> {
        let mut p = parts.to_vec();
        p.sort();
        tlv(&[0x31], &p.concat())
    }
    /// [tag] EXPLICIT, context-specific constructed
    fn explicit(tag: u32, inner: Vec<u8>) -> Vec<u8> {
        let id = if tag < 31 {
            vec![0xa0 | tag as u8]
        } else if tag < 128 {
            vec![0xbf, tag as u8]
        } else {
            vec![0xbf, 0x80 | (tag >> 7) as u8, (tag & 0x7f) as u8]
        };
        tlv(&id, &inner)
    }

    #[derive(Clone)]
    pub struct Spec {
        pub level: u64,
        pub challenge: Vec<u8>,
        pub package: String,
        pub signer: Vec<u8>,
        pub locked: bool,
        pub boot_state: u64,
        pub boot_key: Vec<u8>,
        pub patch: u64,
        pub origin: u64,
    }

    pub fn key_description(s: &Spec) -> Vec<u8> {
        let app_id = seq(&[set(&[seq(&[octets(s.package.as_bytes()), int(3)])]), set(&[octets(&s.signer)])]);
        let software = seq(&[explicit(701, int(1_791_590_400_000)), explicit(709, octets(&app_id))]);
        let rot = seq(&[
            octets(&s.boot_key),
            tlv(&[0x01], &[if s.locked { 0xff } else { 0 }]),
            enumerated(s.boot_state),
            octets(&[0x5a; 32]),
        ]);
        let hardware = seq(&[
            explicit(1, set(&[int(2), int(3)])),
            explicit(2, int(3)),
            explicit(3, int(256)),
            explicit(10, int(1)),
            explicit(503, tlv(&[0x05], &[])),
            explicit(702, int(s.origin)),
            explicit(704, rot),
            explicit(705, int(150_000)),
            explicit(706, int(s.patch)),
            explicit(718, int(20_220_105)),
            explicit(719, int(s.patch * 100 + 5)),
        ]);
        seq(&[
            int(3),
            enumerated(s.level),
            int(4),
            enumerated(s.level),
            octets(&s.challenge),
            octets(&[]),
            software,
            hardware,
        ])
    }

    const KD_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17];

    pub struct Built {
        pub ders: Vec<Vec<u8>>,
        pub root: TrustedRoot,
        pub leaf: EcdsaKeyPair,
    }

    fn dn(cn: &str, title: Option<&str>) -> DistinguishedName {
        let mut d = DistinguishedName::new();
        d.push(DnType::CommonName, cn);
        if let Some(t) = title {
            d.push(DnType::CustomDnType(vec![2, 5, 4, 12]), t);
        }
        d
    }

    fn ca(cn: &str, title: Option<&str>) -> CertificateParams {
        let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
        p.distinguished_name = dn(cn, title);
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        p
    }

    /// test root → intermediate (title=StrongBox unless told otherwise) → leaf with `spec`
    pub fn build(spec: &Spec, strongbox_title: bool, extra_ext_on_intermediate: bool) -> Built {
        let rng = SystemRandom::new();
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let root_params = ca("Phone Vault TEST-ONLY attestation root (not Google)", None);
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_issuer = Issuer::new(root_params, root_key);

        let int_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut int_params = ca("test batch key", Some(if strongbox_title { "StrongBox" } else { "TEE" }));
        if extra_ext_on_intermediate {
            int_params.custom_extensions.push(CustomExtension::from_oid_content(KD_OID, key_description(spec)));
        }
        let int_cert = int_params.signed_by(&int_key, &root_issuer).unwrap();
        let int_issuer = Issuer::new(int_params, int_key);

        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let leaf = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let leaf_rc = KeyPair::try_from(pkcs8.as_ref()).unwrap();
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf_params.distinguished_name = dn("Android Keystore Key", None);
        leaf_params.custom_extensions.push(CustomExtension::from_oid_content(KD_OID, key_description(spec)));
        let leaf_cert = leaf_params.signed_by(&leaf_rc, &int_issuer).unwrap();

        let root_spki = {
            let (_, c) = x509_parser::parse_x509_certificate(root_cert.der()).unwrap();
            c.public_key().raw.to_vec()
        };
        Built {
            ders: vec![leaf_cert.der().to_vec(), int_cert.der().to_vec(), root_cert.der().to_vec()],
            root: TrustedRoot { name: "TEST ROOT", spki: root_spki },
            leaf,
        }
    }

    pub const ADDRESS: &str = "0x52908400098527886e0f7030069857d2e4169ee7";

    pub fn genuine_spec(challenge: &[u8]) -> Spec {
        Spec {
            level: 2,
            challenge: challenge.to_vec(),
            package: "dev.phonevault.signer".into(),
            signer: vec![0xab; 32],
            locked: true,
            boot_state: 1,
            boot_key: vec![0xcd; 32],
            patch: 202_609,
            origin: 0,
        }
    }

    pub fn test_policy() -> Policy {
        Policy {
            package: "dev.phonevault.signer".into(),
            release_signers: vec![vec![0xab; 32]],
            development_signers: vec![vec![0xde; 32]],
            avb_keys: vec![vec![0xcd; 32]],
            min_os_patch_level: 202_501,
        }
    }

    /// The phone's answer, signed like AttestationKey.java does.
    pub fn answer(b: &Built, id: &str, challenge: &[u8], address: &str, level: &str) -> Value {
        let rng = SystemRandom::new();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hex::decode(&address[2..]).unwrap());
        let sig = b.leaf.sign(&rng, &binding_message(challenge, &addr)).unwrap();
        json!({"id": id, "status": "ok", "version": "1", "address": address, "securityLevel": level,
               "certificates": b.ders.iter().map(|d| B64.encode(d)).collect::<Vec<_>>().join(","),
               "signature": format!("0x{}", hex::encode(sig.as_ref()))})
    }

    fn run(_b: &Built, challenge_sent: &[u8], response: &Value, policy: &Policy, roots: &[TrustedRoot]) -> Report {
        let req = request("t1", challenge_sent);
        assess(policy, roots, NOW, challenge_sent, &req, response, unchecked, false).unwrap()
    }

    #[test]
    fn genuine_end_to_end_under_a_test_root() {
        let challenge = [0x42u8; 32];
        let b = build(&genuine_spec(&challenge), true, false);
        let resp = answer(&b, "t1", &challenge, ADDRESS, "StrongBox");
        let r = run(&b, &challenge, &resp, &test_policy(), std::slice::from_ref(&b.root));
        assert_eq!(r.verdict(), Verdict::Genuine, "{r:?}");
        assert_eq!(r.address.as_deref(), Some("0x52908400098527886E0F7030069857D2E4169EE7"));
        let d = r.assessment.details.unwrap();
        assert_eq!(d.verified_boot_state.as_deref(), Some("Self-signed (yellow)"));
        assert_eq!(d.app_package.as_deref(), Some("dev.phonevault.signer"));
        assert!(b.leaf.public_key().as_ref().len() == 65);
    }

    #[test]
    fn same_chain_fails_against_googles_roots() {
        let challenge = [0x42u8; 32];
        let b = build(&genuine_spec(&challenge), true, false);
        let resp = answer(&b, "t1", &challenge, ADDRESS, "StrongBox");
        let r = run(&b, &challenge, &resp, &test_policy(), &roots());
        assert_eq!(r.verdict(), Verdict::Fail);
        assert!(r.assessment.problems[0].contains("Google hardware attestation root"), "{:?}", r.assessment.problems);
    }

    #[test]
    fn address_and_challenge_are_bound() {
        let challenge = [0x42u8; 32];
        let b = build(&genuine_spec(&challenge), true, false);
        // the phone signs one address but reports another (a substituted address)
        let mut resp = answer(&b, "t1", &challenge, ADDRESS, "StrongBox");
        resp["address"] = json!("0xde709f2102306220921060314715629080e2fb77");
        let r = run(&b, &challenge, &resp, &test_policy(), std::slice::from_ref(&b.root));
        assert_eq!(r.verdict(), Verdict::Fail);
        assert!(r.assessment.problems.iter().any(|p| p.contains("not signed by the key in the genuine check")));
        // an old attestation replayed against a new challenge
        let resp = answer(&b, "t1", &challenge, ADDRESS, "StrongBox");
        let r = run(&b, &[0x43u8; 32], &resp, &test_policy(), std::slice::from_ref(&b.root));
        assert_eq!(r.verdict(), Verdict::Fail);
        assert!(r.assessment.problems.iter().any(|p| p.contains("different challenge")), "{:?}", r.assessment.problems);
    }

    /// root → `ints` intermediates (each tweaked by `tweak(index)`) → a plain leaf, as DER, leaf first.
    fn ca_ladder(ints: usize, tweak: impl Fn(usize, &mut CertificateParams)) -> (Vec<Vec<u8>>, TrustedRoot) {
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let root_params = ca("ladder root", None);
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_spki = {
            let (_, c) = x509_parser::parse_x509_certificate(root_cert.der()).unwrap();
            c.public_key().raw.to_vec()
        };
        let mut issuer = Issuer::new(root_params, root_key);
        let mut ders = vec![root_cert.der().to_vec()];
        for i in 0..ints {
            let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
            let mut p = ca(&format!("ladder int {i}"), Some("StrongBox"));
            tweak(i, &mut p);
            ders.insert(0, p.signed_by(&key, &issuer).unwrap().der().to_vec());
            issuer = Issuer::new(p, key);
        }
        let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut leaf = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf.distinguished_name = dn("Android Keystore Key", None);
        ders.insert(0, leaf.signed_by(&leaf_key, &issuer).unwrap().der().to_vec());
        (ders, TrustedRoot { name: "TEST ROOT", spki: root_spki })
    }

    #[test]
    fn intermediates_must_be_cas_that_may_sign_certificates() {
        let err = |ints: usize, tweak: &dyn Fn(usize, &mut CertificateParams)| {
            let (ders, root) = ca_ladder(ints, tweak);
            chain::verify(&ders, &[root], NOW).err().unwrap_or_default()
        };
        // control: a well-formed ladder gets past the CA checks (and stops at the missing extension)
        assert!(err(2, &|_, _| {}).contains("no attestation extension"), "{}", err(2, &|_, _| {}));
        assert!(err(1, &|_, p| p.is_ca = IsCa::ExplicitNoCa).contains("cA=FALSE"));
        assert!(err(1, &|_, p| p.is_ca = IsCa::NoCa).contains("no basic constraints"));
        assert!(err(1, &|_, p| p.key_usages = vec![KeyUsagePurpose::DigitalSignature]).contains("keyCertSign"));
        assert!(err(1, &|_, p| p.key_usages = vec![]).contains("no key usage"));
        // pathLen: the intermediate right under the root allows 0 CAs below it, the chain has 1
        assert!(err(2, &|i, p| if i == 0 {
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0))
        })
        .contains("allows 0"));
        assert!(err(2, &|i, p| if i == 0 {
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(1))
        })
        .contains("no attestation extension"));
    }

    #[test]
    fn chain_extension_attack_and_fake_strongbox_fail() {
        let challenge = [0x42u8; 32];
        let b = build(&genuine_spec(&challenge), true, true);
        let r = run(
            &b,
            &challenge,
            &answer(&b, "t1", &challenge, ADDRESS, "StrongBox"),
            &test_policy(),
            std::slice::from_ref(&b.root),
        );
        assert_eq!(r.verdict(), Verdict::Fail);
        assert!(r.assessment.problems[0].contains("chain-extension"), "{:?}", r.assessment.problems);
        let b = build(&genuine_spec(&challenge), false, false);
        let r = run(
            &b,
            &challenge,
            &answer(&b, "t1", &challenge, ADDRESS, "StrongBox"),
            &test_policy(),
            std::slice::from_ref(&b.root),
        );
        assert_eq!(r.verdict(), Verdict::Fail);
        assert!(r.assessment.problems.iter().any(|p| p.contains("not a StrongBox chain")));
    }

    #[test]
    fn unlocked_dev_phone_is_development_and_dev_signer_needs_dev_mode() {
        let challenge = [0x42u8; 32];
        let mut s = genuine_spec(&challenge);
        s.locked = false;
        s.boot_state = 2;
        s.signer = vec![0xde; 32];
        let b = build(&s, true, false);
        let resp = answer(&b, "t1", &challenge, ADDRESS, "StrongBox");
        let req = request("t1", &challenge);
        let r = assess(&test_policy(), std::slice::from_ref(&b.root), NOW, &challenge, &req, &resp, unchecked, true)
            .unwrap();
        assert_eq!(r.verdict(), Verdict::Development, "{r:?}");
        assert_eq!(r.assessment.headline, policy::UNLOCKED_HEADLINE);
        assert!(r.dev_mode);
        let r = assess(&test_policy(), std::slice::from_ref(&b.root), NOW, &challenge, &req, &resp, unchecked, false)
            .unwrap();
        assert_eq!(r.verdict(), Verdict::Fail);
    }

    #[test]
    fn keydescription_round_trips_through_the_parser() {
        let s = genuine_spec(&[9u8; 16]);
        let kd = keydesc::parse(&key_description(&s)).unwrap();
        assert_eq!(kd.challenge, vec![9u8; 16]);
        assert_eq!(kd.hardware.root_of_trust.as_ref().unwrap().verified_boot_state, BootState::SelfSigned);
        assert_eq!(kd.software.app_id.as_ref().unwrap().packages[0].name, "dev.phonevault.signer");
        assert_eq!(kd.hardware.boot_patch_level, Some(20_260_905));
        assert!(kd.hardware.no_auth_required);
        // trailing junk after the KeyDescription is refused
        let mut bad = key_description(&s);
        bad.push(0);
        assert!(keydesc::parse(&bad).is_err());
    }
}

/// A check that read Developer mode as ON must not cache its verdict when the user turned Developer
/// mode off while it ran. The setting is read after the epoch, and `set_developer_mode` writes the
/// setting before bumping the epoch, so the check's epoch is stale and its (DEVELOPMENT) verdict is
/// dropped instead of cached.
#[test]
fn developer_mode_turned_off_mid_check_is_not_undone() {
    // the user turns Developer mode off exactly while the check reads the (old, ON) setting
    let (epoch, allow_dev) = epoch_then_dev_mode(|| {
        let old = true;
        invalidate();
        old
    })
    .unwrap();
    assert!(allow_dev);
    assert_ne!(epoch, STATE.lock().unwrap().epoch, "the in-flight check's verdict will not be cached");
}
