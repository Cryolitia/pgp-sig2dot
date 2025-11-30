use num_enum::{FromPrimitive, IntoPrimitive};
use sequoia_openpgp::types::SignatureType;
use serde::Serialize;
use serialize_display_adapter_macro_derive::JsonSerializeDisplayAdapter;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

#[derive(Debug, Clone, Eq, Serialize, JsonSerializeDisplayAdapter)]
pub struct OpenPgpKey {
    pub id: Arc<String>,
    pub is_revoked: bool,
    pub is_expired: bool,
    pub user_ids: HashMap<Arc<String>, OpenPgpUid>,
    pub primary_user_id: Arc<String>,
}

impl PartialEq for OpenPgpKey {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Hash for OpenPgpKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl Borrow<str> for OpenPgpKey {
    fn borrow(&self) -> &str {
        self.id.as_str()
    }
}

#[derive(Debug, Clone, Eq, Serialize)]
pub struct OpenPgpUid {
    pub fingerprint: Arc<String>,
    pub uid: Arc<String>,
    pub name: String,
    pub email: String,
    pub comment: String,
    #[serde(skip_serializing)]
    pub sig_vec: Vec<OpenPgpSig>,
    pub is_revoked: bool,
    pub is_primary: bool,
}

impl PartialEq for OpenPgpUid {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint && self.uid == other.uid
    }
}

impl Hash for OpenPgpUid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.fingerprint.hash(state);
        self.uid.hash(state);
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct GraphNodeUid<'a> {
    pub fingerprint: &'a str,
    pub uid: &'a str,
}

pub(crate) trait OpenPgpUidKey {
    fn key(&self) -> &str;
    fn uid(&self) -> &str;
}

impl<'a> Borrow<dyn OpenPgpUidKey + 'a> for OpenPgpUid {
    fn borrow(&self) -> &(dyn OpenPgpUidKey + 'a) {
        self
    }
}

impl<'a> Borrow<dyn OpenPgpUidKey + 'a> for OpenPgpSig {
    fn borrow(&self) -> &(dyn OpenPgpUidKey + 'a) {
        self
    }
}

impl Hash for dyn OpenPgpUidKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key().hash(state);
        self.uid().hash(state);
    }
}

impl PartialEq for dyn OpenPgpUidKey {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key() && self.uid() == other.uid()
    }
}

impl Eq for dyn OpenPgpUidKey {}

impl OpenPgpUidKey for OpenPgpUid {
    fn key(&self) -> &str {
        &self.fingerprint
    }
    fn uid(&self) -> &str {
        &self.uid
    }
}

impl OpenPgpUidKey for &OpenPgpUid {
    fn key(&self) -> &str {
        self.fingerprint.as_str()
    }
    fn uid(&self) -> &str {
        self.uid.as_str()
    }
}

impl OpenPgpUidKey for OpenPgpSig {
    fn key(&self) -> &str {
        self.fingerprint.as_str()
    }
    fn uid(&self) -> &str {
        self.uid.as_str()
    }
}

impl OpenPgpUidKey for &OpenPgpSig {
    fn key(&self) -> &str {
        self.fingerprint.as_str()
    }
    fn uid(&self) -> &str {
        self.uid.as_str()
    }
}

impl OpenPgpUidKey for GraphNodeUid<'_> {
    fn key(&self) -> &str {
        self.fingerprint
    }
    fn uid(&self) -> &str {
        self.uid
    }
}

impl OpenPgpUidKey for &GraphNodeUid<'_> {
    fn key(&self) -> &str {
        self.fingerprint
    }
    fn uid(&self) -> &str {
        self.uid
    }
}

impl<'a> From<&'a OpenPgpUid> for GraphNodeUid<'a> {
    fn from(value: &'a OpenPgpUid) -> Self {
        GraphNodeUid {
            fingerprint: value.fingerprint.as_str(),
            uid: value.uid.as_str(),
        }
    }
}

impl<'a> From<&&'a OpenPgpUid> for GraphNodeUid<'a> {
    fn from(value: &&'a OpenPgpUid) -> Self {
        GraphNodeUid {
            fingerprint: value.fingerprint.as_str(),
            uid: value.uid.as_str(),
        }
    }
}

impl<'a> From<&'a OpenPgpSig> for GraphNodeUid<'a> {
    fn from(value: &'a OpenPgpSig) -> Self {
        GraphNodeUid {
            fingerprint: value.fingerprint.as_str(),
            uid: value.uid.as_str(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct OpenPgpSig {
    pub fingerprint: String,
    pub uid: String,
    pub trust_level: u8,
    pub trust_value: OpenPgpSigTrust,
    pub sig_type: SigType,
    pub creation_time: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub struct GraphEdgeSig {
    pub(crate) trust_level: u8,
    pub(crate) trust_value: OpenPgpSigTrust,
    pub(crate) sig_type: SigType,
    pub(crate) creation_time: u64,
}

impl From<&OpenPgpSig> for GraphEdgeSig {
    fn from(value: &OpenPgpSig) -> Self {
        GraphEdgeSig {
            trust_level: value.trust_level,
            trust_value: value.trust_value,
            sig_type: value.sig_type,
            creation_time: value.creation_time,
        }
    }
}

#[derive(
    IntoPrimitive,
    FromPrimitive,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Copy,
    Clone,
    Default,
    Serialize,
    JsonSerializeDisplayAdapter,
)]
#[repr(u8)]
pub(crate) enum OpenPgpValidity {
    #[default]
    Unknown = 0,
    Undefined = 1,
    Never = 2,
    Marginal = 3,
    Full = 4,
    Ultimate = 5,
}

#[derive(
    FromPrimitive,
    IntoPrimitive,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Copy,
    Clone,
    Default,
    Serialize,
    JsonSerializeDisplayAdapter,
)]
#[repr(u8)]
pub enum OpenPgpSigTrust {
    #[default]
    None = 0,
    #[num_enum(alternatives = [1..60, 61..120])]
    Partial = 60,
    #[num_enum(alternatives = [121..=255])]
    Complete = 120,
}

#[derive(
    FromPrimitive,
    IntoPrimitive,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Debug,
    Copy,
    Clone,
    Serialize,
    JsonSerializeDisplayAdapter,
)]
#[repr(u8)]
pub enum SigType {
    Default = 0x10,
    NotAtAll = 0x11,
    Casual = 0x12,
    Careful = 0x13,
    Revoke = 0x30,
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl From<SignatureType> for SigType {
    fn from(value: SignatureType) -> Self {
        match value {
            SignatureType::GenericCertification => SigType::Default,
            SignatureType::PersonaCertification => SigType::NotAtAll,
            SignatureType::CasualCertification => SigType::Casual,
            SignatureType::PositiveCertification => SigType::Careful,
            SignatureType::CertificationRevocation => SigType::Revoke,
            _ => SigType::Unknown(value.into()),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct GraphNodeUidOwned {
    pub fingerprint: String,
    pub uid: String,
}

impl<'a> From<&'a GraphNodeUidOwned> for GraphNodeUid<'a> {
    fn from(value: &'a GraphNodeUidOwned) -> Self {
        GraphNodeUid {
            fingerprint: value.fingerprint.as_str(),
            uid: value.uid.as_str(),
        }
    }
}
