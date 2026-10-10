//! The Android key attestation extension (OID 1.3.6.1.4.1.11129.2.1.17), parsed per the
//! KeyDescription schema in https://source.android.com/docs/security/features/keystore/attestation#schema
//!
//! ```text
//! KeyDescription ::= SEQUENCE {
//!     attestationVersion         INTEGER,
//!     attestationSecurityLevel   SecurityLevel,
//!     keyMintVersion             INTEGER,          -- keymasterVersion before KeyMint
//!     keyMintSecurityLevel       SecurityLevel,
//!     attestationChallenge       OCTET_STRING,
//!     uniqueId                   OCTET_STRING,
//!     softwareEnforced           AuthorizationList,
//!     hardwareEnforced           AuthorizationList, -- teeEnforced before KeyMint
//! }
//! SecurityLevel ::= ENUMERATED { Software (0), TrustedEnvironment (1), StrongBox (2) }
//! RootOfTrust ::= SEQUENCE {
//!     verifiedBootKey   OCTET_STRING,
//!     deviceLocked      BOOLEAN,
//!     verifiedBootState VerifiedBootState,
//!     verifiedBootHash  OCTET_STRING,              -- attestation version >= 3
//! }
//! VerifiedBootState ::= ENUMERATED { Verified (0), SelfSigned (1), Unverified (2), Failed (3) }
//! AttestationApplicationId ::= SEQUENCE {
//!     package_infos     SET OF AttestationPackageInfo,
//!     signature_digests SET OF OCTET_STRING,       -- SHA-256 of each signing certificate
//! }
//! AttestationPackageInfo ::= SEQUENCE { package_name OCTET_STRING, version INTEGER }
//! ```
//!
//! An AuthorizationList is a SEQUENCE of optional `[tag] EXPLICIT` fields in ascending tag order.
//! Tags this verifier relies on are type-checked; other tags are skipped, but the ascending
//! order (which also rules out duplicates) is enforced for every tag.

use super::der::{Reader, CLASS_CONTEXT, CLASS_UNIVERSAL, TAG_NULL};
use serde::Serialize;

pub const OID_KEY_DESCRIPTION: &str = "1.3.6.1.4.1.11129.2.1.17";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SecurityLevel { Software, TrustedEnvironment, StrongBox }

impl SecurityLevel {
    fn from(v: u64) -> Result<Self, String> {
        match v { 0 => Ok(Self::Software), 1 => Ok(Self::TrustedEnvironment), 2 => Ok(Self::StrongBox), _ => Err(format!("attestation extension: unknown security level {v}")) }
    }
    pub fn name(self) -> &'static str {
        match self { Self::Software => "Software", Self::TrustedEnvironment => "TrustedEnvironment", Self::StrongBox => "StrongBox" }
    }
    pub fn parse_name(s: &str) -> Option<Self> {
        match s { "Software" => Some(Self::Software), "TrustedEnvironment" => Some(Self::TrustedEnvironment), "StrongBox" => Some(Self::StrongBox), _ => None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BootState { Verified, SelfSigned, Unverified, Failed }

impl BootState {
    fn from(v: u64) -> Result<Self, String> {
        match v { 0 => Ok(Self::Verified), 1 => Ok(Self::SelfSigned), 2 => Ok(Self::Unverified), 3 => Ok(Self::Failed), _ => Err(format!("attestation extension: unknown verified boot state {v}")) }
    }
    pub fn describe(self) -> &'static str {
        match self {
            Self::Verified => "Verified (green)",
            Self::SelfSigned => "Self-signed (yellow)",
            Self::Unverified => "Unverified (orange: bootloader unlocked)",
            Self::Failed => "Failed (red)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootOfTrust {
    pub verified_boot_key: Vec<u8>,
    pub device_locked: bool,
    pub verified_boot_state: BootState,
    pub verified_boot_hash: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo { pub name: String, pub version: u64 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppId { pub packages: Vec<PackageInfo>, pub signature_digests: Vec<Vec<u8>> }

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthList {
    pub purposes: Vec<u64>,
    pub algorithm: Option<u64>,
    pub key_size: Option<u64>,
    pub ec_curve: Option<u64>,
    pub no_auth_required: bool,
    pub creation_datetime: Option<u64>,
    pub origin: Option<u64>,
    pub root_of_trust: Option<RootOfTrust>,
    pub os_version: Option<u64>,
    pub os_patch_level: Option<u64>,
    pub app_id: Option<AppId>,
    pub vendor_patch_level: Option<u64>,
    pub boot_patch_level: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDescription {
    pub attestation_version: u64,
    pub attestation_security_level: SecurityLevel,
    pub keymint_version: u64,
    pub keymint_security_level: SecurityLevel,
    pub challenge: Vec<u8>,
    pub unique_id: Vec<u8>,
    pub software: AuthList,
    pub hardware: AuthList,
}

pub const ORIGIN_GENERATED: u64 = 0;
pub const ALGORITHM_EC: u64 = 3;
pub const CURVE_P256: u64 = 1;

const TAG_PURPOSE: u32 = 1;
const TAG_ALGORITHM: u32 = 2;
const TAG_KEY_SIZE: u32 = 3;
const TAG_EC_CURVE: u32 = 10;
const TAG_NO_AUTH_REQUIRED: u32 = 503;
const TAG_CREATION_DATETIME: u32 = 701;
const TAG_ORIGIN: u32 = 702;
const TAG_ROOT_OF_TRUST: u32 = 704;
const TAG_OS_VERSION: u32 = 705;
const TAG_OS_PATCH_LEVEL: u32 = 706;
const TAG_APP_ID: u32 = 709;
const TAG_VENDOR_PATCH_LEVEL: u32 = 718;
const TAG_BOOT_PATCH_LEVEL: u32 = 719;

pub fn parse(ext: &[u8]) -> Result<KeyDescription, String> {
    let mut outer = Reader::new(ext);
    let mut s = outer.sequence("KeyDescription")?;
    outer.end("the extension")?;
    let attestation_version = s.uint("attestationVersion")?;
    let attestation_security_level = SecurityLevel::from(s.enumerated("attestationSecurityLevel")?)?;
    let keymint_version = s.uint("keyMintVersion")?;
    let keymint_security_level = SecurityLevel::from(s.enumerated("keyMintSecurityLevel")?)?;
    let challenge = s.octets("attestationChallenge")?.to_vec();
    let unique_id = s.octets("uniqueId")?.to_vec();
    let software = auth_list(&mut s.sequence("softwareEnforced")?, "softwareEnforced")?;
    let hardware = auth_list(&mut s.sequence("hardwareEnforced")?, "hardwareEnforced")?;
    s.end("KeyDescription")?;
    Ok(KeyDescription { attestation_version, attestation_security_level, keymint_version, keymint_security_level, challenge, unique_id, software, hardware })
}

fn auth_list(r: &mut Reader, which: &str) -> Result<AuthList, String> {
    let mut list = AuthList::default();
    let mut last: Option<u32> = None;
    while !r.is_empty() {
        let field = r.read()?;
        if field.class != CLASS_CONTEXT || !field.constructed {
            return Err(format!("attestation extension: {which} holds an untagged field"));
        }
        if let Some(prev) = last {
            if field.tag <= prev { return Err(format!("attestation extension: {which} tags are not in ascending order ([{}] after [{prev}])", field.tag)); }
        }
        last = Some(field.tag);
        let mut inner = Reader::new(field.value);
        let name = format!("{which} [{}]", field.tag);
        match field.tag {
            TAG_PURPOSE => {
                let mut set = inner.set(&name)?;
                while !set.is_empty() { list.purposes.push(set.uint(&name)?); }
            }
            TAG_ALGORITHM => list.algorithm = Some(inner.uint(&name)?),
            TAG_KEY_SIZE => list.key_size = Some(inner.uint(&name)?),
            TAG_EC_CURVE => list.ec_curve = Some(inner.uint(&name)?),
            TAG_NO_AUTH_REQUIRED => { inner.expect(CLASS_UNIVERSAL, false, TAG_NULL, &name)?; list.no_auth_required = true; }
            TAG_CREATION_DATETIME => list.creation_datetime = Some(inner.uint(&name)?),
            TAG_ORIGIN => list.origin = Some(inner.uint(&name)?),
            TAG_ROOT_OF_TRUST => list.root_of_trust = Some(root_of_trust(&mut inner.sequence(&name)?)?),
            TAG_OS_VERSION => list.os_version = Some(inner.uint(&name)?),
            TAG_OS_PATCH_LEVEL => list.os_patch_level = Some(inner.uint(&name)?),
            TAG_APP_ID => list.app_id = Some(app_id(inner.octets(&name)?)?),
            TAG_VENDOR_PATCH_LEVEL => list.vendor_patch_level = Some(inner.uint(&name)?),
            TAG_BOOT_PATCH_LEVEL => list.boot_patch_level = Some(inner.uint(&name)?),
            _ => { inner.read()?; } // a field we don't rely on: one well-formed element, nothing else
        }
        inner.end(&name)?;
    }
    Ok(list)
}

fn root_of_trust(r: &mut Reader) -> Result<RootOfTrust, String> {
    let verified_boot_key = r.octets("rootOfTrust.verifiedBootKey")?.to_vec();
    let device_locked = r.boolean("rootOfTrust.deviceLocked")?;
    let verified_boot_state = BootState::from(r.enumerated("rootOfTrust.verifiedBootState")?)?;
    let verified_boot_hash = if r.is_empty() { None } else { Some(r.octets("rootOfTrust.verifiedBootHash")?.to_vec()) };
    r.end("rootOfTrust")?;
    Ok(RootOfTrust { verified_boot_key, device_locked, verified_boot_state, verified_boot_hash })
}

fn app_id(bytes: &[u8]) -> Result<AppId, String> {
    let mut outer = Reader::new(bytes);
    let mut s = outer.sequence("attestationApplicationId")?;
    outer.end("attestationApplicationId")?;
    let mut packages = Vec::new();
    let mut infos = s.set("attestationApplicationId.package_infos")?;
    while !infos.is_empty() {
        let mut p = infos.sequence("AttestationPackageInfo")?;
        let name = std::str::from_utf8(p.octets("package_name")?).map_err(|_| "attestation extension: package name is not UTF-8".to_string())?.to_string();
        let version = p.uint("package version")?;
        p.end("AttestationPackageInfo")?;
        packages.push(PackageInfo { name, version });
    }
    let mut signature_digests = Vec::new();
    let mut digests = s.set("attestationApplicationId.signature_digests")?;
    while !digests.is_empty() { signature_digests.push(digests.octets("signature digest")?.to_vec()); }
    s.end("attestationApplicationId")?;
    Ok(AppId { packages, signature_digests })
}

/// "15.0.0" from 150000 (MMmmpp).
pub fn os_version_text(v: u64) -> String { format!("{}.{}.{}", v / 10000, (v / 100) % 100, v % 100) }

/// "2026-09" from 202609, "2026-09-05" from 20260905; anything else as the raw number.
pub fn patch_level_text(v: u64) -> String {
    let s = v.to_string();
    match s.len() { 6 => format!("{}-{}", &s[..4], &s[4..]), 8 => format!("{}-{}-{}", &s[..4], &s[4..6], &s[6..]), _ => s }
}

/// YYYYMM from a YYYYMM or YYYYMMDD value (for comparisons).
pub fn patch_month(v: u64) -> u64 { if v > 9_999_99 { v / 100 } else { v } }
