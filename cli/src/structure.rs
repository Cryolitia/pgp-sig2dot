use crate::cli::OutputType::Dot;
use crate::{DRAW_OPTIONS, GOSSIP_LAYER_MAP, KEY_SET_MAP};
use pgp_sig2dot::get_pgp_uid_by_node_uid;
use pgp_sig2dot::structure::{GraphEdgeSig, GraphNodeUid, OpenPgpSig, OpenPgpUid};
use serde::Serialize;
use std::fmt::Formatter;
use std::sync::Arc;

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

#[derive(Debug, Clone, Serialize)]
pub struct OpenPgpUidLayer {
    pub fingerprint: Arc<String>,
    pub uid: Arc<String>,
    pub name: String,
    pub email: String,
    pub comment: String,
    pub is_revoked: bool,
    pub is_primary: bool,
    pub layer: i16,
}

pub(crate) fn simple_output<T>(object: &T, f: &mut Formatter<'_>, or: &String) -> std::fmt::Result
where
    T: Serialize,
{
    let simple_output = DRAW_OPTIONS
        .get()
        .map(|args| args.output.output_type == Dot)
        .unwrap_or(false);
    if !simple_output {
        write!(
            f,
            "{}",
            serde_json::to_string(object).unwrap_or_else(|e| format!("{e}"))
        )
    } else {
        write!(f, "{or}")
    }
}

pub(crate) fn complex_output(
    object: &OpenPgpUid,
    f: &mut Formatter<'_>,
    or: &String,
) -> std::fmt::Result {
    let gossip_output = DRAW_OPTIONS
        .get()
        .map(|args| args.processor.gossip)
        .unwrap_or(None)
        .is_some();
    if gossip_output {
        simple_output(&<&OpenPgpUid as Into<OpenPgpUidLayer>>::into(object), f, or)
    } else {
        simple_output(object, f, or)
    }
}

pub fn graph_node_uid_fmt(item: &GraphNodeUid<'_>, f: &mut Formatter<'_>) -> std::fmt::Result {
    match get_pgp_uid_by_node_uid(&KEY_SET_MAP, item) {
        None => simple_output(item, f, &item.fingerprint.to_string()),
        Some(v) => complex_output(v, f, &v.uid.to_string()),
    }
}

pub fn open_pgp_sig_fmt(item: &&OpenPgpSig, f: &mut Formatter<'_>) -> std::fmt::Result {
    simple_output(
        &<&OpenPgpSig as Into<GraphEdgeSig>>::into(item),
        f,
        &item.sig_type.to_string().replace("\"", ""),
    )
}
