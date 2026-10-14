//! Certificate-chain verification for Android key attestation, up to a pinned Google root key.
//!
//! The trust anchors are Google's hardware attestation root PUBLIC KEYS, not certificates: the
//! RSA-4096 root has been re-issued several times with the same key (2016, 2019, 2021, 2022
//! certificates), the 2016 certificate that factory-provisioned Pixel 3 chains still carry
//! expired on 2026-05-24, and Google's guidance is to trust the key. Source:
//! https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
//! (the same set is served as JSON at https://android.googleapis.com/attestation/root; a copy
//! fetched 2026-10-10 is in testdata/google_roots.json and a unit test re-derives both keys).
//!
//! Checks, in order (each failure is a hard failure):
//! 1. 2..=8 certificates, each a complete DER X.509 v3 certificate with no trailing bytes.
//! 2. The last certificate's SubjectPublicKeyInfo is byte-identical to a pinned root key.
//! 3. For every link: issuer name == next subject name (raw DER), the outer and TBS signature
//!    algorithms agree, and the signature verifies under the next certificate's key, using only
//!    RSA PKCS#1 v1.5 (SHA-256/384/512, 2048..8192 bits) or ECDSA P-256/P-384 (SHA-256/384).
//!    SHA-1, PSS and anything else are refused.
//!    Every certificate between the leaf and the root must carry basicConstraints cA=TRUE and a
//!    keyUsage with keyCertSign, and its pathLenConstraint (if any) must cover the CA
//!    certificates under it. (The root's own extensions, like its dates, are irrelevant: the
//!    anchor is its key.)
//! 4. Validity of every certificate between the leaf and the root at `now`: not-yet-valid fails;
//!    expired fails, except for factory-provisioned chains, which Google's reference verifier
//!    (github.com/android/keyattestation, KeyAttestationCertPathValidator) tolerates because
//!    factory keys cannot be rotated; that case is reported as a note. The leaf's own validity
//!    is set on the phone from its (offline, possibly wrong) clock and is reported, not enforced,
//!    exactly like the reference verifier. The root certificate's dates are irrelevant: the
//!    anchor is its key.
//! 5. The attestation extension appears in the leaf and in no other certificate (chain-extension
//!    attack: a key the attacker controls, itself attested, signing a forged leaf).

use super::keydesc::{self, KeyDescription};
use base64::Engine;
use ring::signature;
use x509_parser::prelude::*;

pub const MAX_CHAIN: usize = 8;
const MAX_CERT_BYTES: usize = 8192;

/// Google Hardware Attestation Root, RSA-4096 (subject serialNumber=f92009e853b6b045). The
/// certificates issued 2016, 2019, 2021 and 2022 all carry this SubjectPublicKeyInfo
/// (SHA-256 feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae).
const GOOGLE_RSA_ROOT_SPKI: &str = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==";

/// "Key Attestation CA1" (O=Google LLC, OU=Android), ECDSA P-384, signing attestation chains
/// from 2026-02-01 (SHA-256 of the SPKI 3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec).
const GOOGLE_EC_ROOT_SPKI: &str = "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikNMHnu4fkRzObfgDkU2KNXezT9/RQ+XvNslxPHrHCowhGr";

#[derive(Debug, Clone)]
pub struct TrustedRoot { pub name: &'static str, pub spki: Vec<u8> }

pub fn google_roots() -> Vec<TrustedRoot> {
    let d = |s: &str| base64::engine::general_purpose::STANDARD.decode(s).expect("embedded root key is valid base64");
    vec![
        TrustedRoot { name: "Google Hardware Attestation Root (RSA)", spki: d(GOOGLE_RSA_ROOT_SPKI) },
        TrustedRoot { name: "Google Key Attestation CA1 (EC, 2026)", spki: d(GOOGLE_EC_ROOT_SPKI) },
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Provisioning { Factory, Remote, Unknown }

#[derive(Debug, Clone)]
pub struct ChainInfo {
    pub description: KeyDescription,
    pub root: &'static str,
    pub provisioning: Provisioning,
    /// An intermediate's subject names StrongBox (CTS: factory chains carry title=StrongBox,
    /// remotely provisioned ones O=StrongBox on the attestation certificate).
    pub chain_names_strongbox: bool,
    /// Uncompressed SEC1 point of the attested key, when it is EC P-256.
    pub leaf_p256_point: Option<Vec<u8>>,
    /// Serial numbers as lowercase hex without leading zeros (the revocation list's format).
    pub serials: Vec<String>,
    pub chain_length: usize,
    pub notes: Vec<String>,
}

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";
const OID_P384: &str = "1.3.132.0.34";
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";
const OID_RSA_SHA512: &str = "1.2.840.113549.1.1.13";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";

fn curve(spki: &SubjectPublicKeyInfo) -> Option<String> {
    spki.algorithm.parameters.as_ref()?.as_oid().ok().map(|o| o.to_id_string())
}

fn verification_alg(sig_oid: &str, issuer: &SubjectPublicKeyInfo) -> Result<&'static dyn signature::VerificationAlgorithm, String> {
    let key = issuer.algorithm.algorithm.to_id_string();
    let c = curve(issuer);
    Ok(match (sig_oid, key.as_str(), c.as_deref()) {
        (OID_RSA_SHA256, OID_RSA, _) => &signature::RSA_PKCS1_2048_8192_SHA256,
        (OID_RSA_SHA384, OID_RSA, _) => &signature::RSA_PKCS1_2048_8192_SHA384,
        (OID_RSA_SHA512, OID_RSA, _) => &signature::RSA_PKCS1_2048_8192_SHA512,
        (OID_ECDSA_SHA256, OID_EC, Some(OID_P256)) => &signature::ECDSA_P256_SHA256_ASN1,
        (OID_ECDSA_SHA384, OID_EC, Some(OID_P256)) => &signature::ECDSA_P256_SHA384_ASN1,
        (OID_ECDSA_SHA256, OID_EC, Some(OID_P384)) => &signature::ECDSA_P384_SHA256_ASN1,
        (OID_ECDSA_SHA384, OID_EC, Some(OID_P384)) => &signature::ECDSA_P384_SHA384_ASN1,
        _ => return Err(format!("unsupported signature algorithm {sig_oid} for a {key} key")),
    })
}

fn has_attestation_ext(c: &X509Certificate) -> bool {
    c.extensions().iter().any(|e| e.oid.to_id_string() == keydesc::OID_KEY_DESCRIPTION)
}

fn names_strongbox(c: &X509Certificate) -> bool {
    c.subject().iter_attributes().any(|a| a.as_str().is_ok_and(|s| s.to_ascii_lowercase().contains("strongbox")))
}

fn has_serial_number_attr(c: &X509Certificate) -> bool {
    c.subject().iter_attributes().any(|a| a.attr_type().to_id_string() == "2.5.4.5")
}

pub fn serial_hex(raw: &[u8]) -> String {
    let s: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let t = s.trim_start_matches('0');
    if t.is_empty() { "0".into() } else { t.into() }
}

/// YYYY-MM-DD (UTC) for a unix time; civil-from-days (Howard Hinnant).
pub fn day_text(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Verify `ders` (leaf first, root last) against `roots` at unix time `now`, and parse the
/// leaf's KeyDescription. Any error is a reason to fail the device.
pub fn verify(ders: &[Vec<u8>], roots: &[TrustedRoot], now: i64) -> Result<ChainInfo, String> {
    if ders.len() < 2 { return Err("the attestation chain is too short".into()); }
    if ders.len() > MAX_CHAIN { return Err(format!("the attestation chain has {} certificates (at most {MAX_CHAIN})", ders.len())); }
    let mut certs = Vec::with_capacity(ders.len());
    for (i, der) in ders.iter().enumerate() {
        if der.len() > MAX_CERT_BYTES { return Err(format!("certificate {i} is too large")); }
        let (rest, cert) = X509Certificate::from_der(der).map_err(|e| format!("certificate {i} is not valid DER X.509: {e}"))?;
        if !rest.is_empty() { return Err(format!("certificate {i} has trailing bytes")); }
        if cert.version() != X509Version::V3 { return Err(format!("certificate {i} is not X.509 v3")); }
        certs.push(cert);
    }
    let last = certs.len() - 1;

    // 2. root key pinned
    let root_spki = certs[last].public_key().raw;
    let root = roots.iter().find(|r| r.spki.as_slice() == root_spki)
        .ok_or("the chain does not end in a Google hardware attestation root key (unknown or software root)")?;

    // 3. links
    for i in 0..last {
        let (cert, issuer) = (&certs[i], &certs[i + 1]);
        if cert.issuer().as_raw() != issuer.subject().as_raw() {
            return Err(format!("certificate {i}'s issuer is not certificate {}'s subject", i + 1));
        }
        let outer = &cert.signature_algorithm;
        let inner = &cert.tbs_certificate.signature;
        if outer.algorithm != inner.algorithm || outer.parameters.as_ref().map(|p| p.as_bytes()) != inner.parameters.as_ref().map(|p| p.as_bytes()) {
            return Err(format!("certificate {i} names two different signature algorithms"));
        }
        let alg = verification_alg(&outer.algorithm.to_id_string(), issuer.public_key()).map_err(|e| format!("certificate {i}: {e}"))?;
        if cert.signature_value.unused_bits != 0 { return Err(format!("certificate {i}'s signature is not whole bytes")); }
        signature::UnparsedPublicKey::new(alg, &issuer.public_key().subject_public_key.data)
            .verify(cert.tbs_certificate.as_ref(), &cert.signature_value.data)
            .map_err(|_| format!("certificate {i}'s signature does not verify under certificate {}", i + 1))?;
    }

    // 3b. every certificate that signs another (below the pinned root) must be a CA allowed to
    // sign certificates, and its path length constraint must cover the CAs under it
    for (i, cert) in certs.iter().enumerate().take(last).skip(1) {
        let bc = cert.basic_constraints().map_err(|e| format!("certificate {i}'s basic constraints are malformed: {e}"))?
            .ok_or_else(|| format!("certificate {i} signs a certificate but is not marked as a CA (no basic constraints)"))?;
        if !bc.value.ca { return Err(format!("certificate {i} signs a certificate but is not a CA (basic constraints cA=FALSE)")); }
        // CA certificates between this one and the leaf
        let below = (i - 1) as u32;
        if let Some(max) = bc.value.path_len_constraint {
            if below > max { return Err(format!("certificate {i} allows {max} CA certificates under it, the chain has {below}")); }
        }
        let ku = cert.key_usage().map_err(|e| format!("certificate {i}'s key usage is malformed: {e}"))?
            .ok_or_else(|| format!("certificate {i} signs a certificate but has no key usage"))?;
        if !ku.value.key_cert_sign() { return Err(format!("certificate {i} signs a certificate but its key usage lacks keyCertSign")); }
    }

    // provisioning (as the reference verifier decides it: the certificate right under the root)
    let top = &certs[last - 1];
    let provisioning = if has_serial_number_attr(top) { Provisioning::Factory }
        else if top.subject().iter_common_name().any(|cn| cn.as_str().ok() == Some("Droid CA2")) { Provisioning::Remote }
        else { Provisioning::Unknown };

    // 4. validity
    let mut notes = Vec::new();
    for (i, cert) in certs.iter().enumerate().take(last).skip(1) {
        let v = cert.validity();
        if v.not_before.timestamp() > now {
            return Err(format!("certificate {i} is not valid until {}", day_text(v.not_before.timestamp())));
        }
        if v.not_after.timestamp() < now {
            if provisioning == Provisioning::Factory {
                notes.push(format!("Factory attestation certificate {i} expired on {} (tolerated for factory keys, as Google's verifier does)", day_text(v.not_after.timestamp())));
            } else {
                return Err(format!("certificate {i} expired on {}", day_text(v.not_after.timestamp())));
            }
        }
    }
    let leaf_validity = certs[0].validity();
    if leaf_validity.not_after.timestamp() < now {
        notes.push(format!("The attested key's certificate says it expired on {} (set from the phone's clock; not enforced)", day_text(leaf_validity.not_after.timestamp())));
    }

    // 5. extension only in the leaf
    for (i, cert) in certs.iter().enumerate().skip(1) {
        if has_attestation_ext(cert) { return Err(format!("certificate {i} also carries an attestation extension (chain-extension attack)")); }
    }
    let exts: Vec<_> = certs[0].extensions().iter().filter(|e| e.oid.to_id_string() == keydesc::OID_KEY_DESCRIPTION).collect();
    if exts.len() != 1 { return Err("the leaf certificate has no attestation extension".into()); }
    let description = keydesc::parse(exts[0].value)?;

    let chain_names_strongbox = certs[1..last].iter().any(names_strongbox);
    let leaf_spki = certs[0].public_key();
    let leaf_p256_point = (leaf_spki.algorithm.algorithm.to_id_string() == OID_EC && curve(leaf_spki).as_deref() == Some(OID_P256))
        .then(|| leaf_spki.subject_public_key.data.to_vec());
    Ok(ChainInfo {
        description,
        root: root.name,
        provisioning,
        chain_names_strongbox,
        leaf_p256_point,
        serials: certs.iter().map(|c| serial_hex(c.raw_serial())).collect(),
        chain_length: certs.len(),
        notes,
    })
}

