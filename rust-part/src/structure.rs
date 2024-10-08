use crate::cert::{complex_output, get_pgp_uid_by_node_uid, simple_output};
use crate::GOSSIP_LAYER_MAP;
use num_enum::{FromPrimitive, IntoPrimitive};
use sequoia_openpgp::types::SignatureType;
use serde::Serialize;
use serialize_display_adapter_macro_derive::JsonSerializeDisplayAdapter;
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

#[derive(Debug, Clone, Eq, Serialize, JsonSerializeDisplayAdapter)]
pub(crate) struct OpenPgpKey {
    pub(crate) id: Arc<String>,
    pub(crate) is_revoked: bool,
    pub(crate) is_expired: bool,
    pub(crate) user_ids: HashMap<Arc<String>, OpenPgpUid>,
    pub(crate) primary_user_id: Arc<String>,
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
pub(crate) struct OpenPgpUid {
    pub(crate) fingerprint: Arc<String>,
    pub(crate) uid: Arc<String>,
    pub(crate) name: String,
    pub(crate) email: String,
    pub(crate) comment: String,
    #[serde(skip_serializing)]
    pub(crate) sig_vec: Vec<OpenPgpSig>,
    pub(crate) is_revoked: bool,
    pub(crate) is_primary: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OpenPgpUidLayer {
    pub(crate) fingerprint: Arc<String>,
    pub(crate) uid: Arc<String>,
    pub(crate) name: String,
    pub(crate) email: String,
    pub(crate) comment: String,
    pub(crate) is_revoked: bool,
    pub(crate) is_primary: bool,
    pub(crate) layer: i16,
}

impl From<&OpenPgpUid> for OpenPgpUidLayer {
    fn from(value: &OpenPgpUid) -> Self {
        let layer: i16 = match GOSSIP_LAYER_MAP
            .get()
            .and_then(|v| v.get(&value.fingerprint))
        {
            None => -1,
            Some(v) => (*v).into(),
        };

        OpenPgpUidLayer {
            fingerprint: value.fingerprint.clone(),
            uid: value.uid.clone(),
            name: value.name.clone(),
            email: value.email.clone(),
            comment: value.comment.clone(),
            is_revoked: value.is_revoked,
            is_primary: value.is_primary,
            layer,
        }
    }
}

impl Display for OpenPgpUid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        simple_output(self, f, self.uid.borrow())
    }
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
pub(crate) struct GraphNodeUid<'a> {
    pub(crate) fingerprint: &'a str,
    pub(crate) uid: &'a str,
}

impl Display for GraphNodeUid<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match get_pgp_uid_by_node_uid(self) {
            None => simple_output(self, f, &self.fingerprint.to_string()),
            Some(v) => complex_output(v, f, &v.uid.to_string()),
        }
    }
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
pub(crate) struct OpenPgpSig {
    pub(crate) fingerprint: String,
    pub(crate) uid: String,
    pub(crate) trust_level: u8,
    pub(crate) trust_value: OpenPgpSigTrust,
    pub(crate) sig_type: SigType,
    pub(crate) creation_time: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
pub(crate) struct GraphEdgeSig {
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

impl Display for OpenPgpSig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        simple_output(
            &<&OpenPgpSig as Into<GraphEdgeSig>>::into(self),
            f,
            &self.sig_type.to_string().replace("\"", ""),
        )
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
pub(crate) enum OpenPgpSigTrust {
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
pub(crate) enum SigType {
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
