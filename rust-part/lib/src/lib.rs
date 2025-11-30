use crate::structure::{GraphNodeUid, OpenPgpKey, OpenPgpUid};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

pub mod cert;
pub mod gossip;
pub mod helper;
pub mod input;
pub mod keyserver;
pub mod structure;

pub fn get_pgp_uid_by_node_uid<'a>(
    key_set_map: &'a OnceLock<HashMap<Arc<std::string::String>, OpenPgpKey>>,
    uid: &'a GraphNodeUid,
) -> Option<&'a OpenPgpUid> {
    key_set_map
        .get()
        .and_then(|v| {
            v.get(&uid.fingerprint.to_string())
                .map(|v| v.user_ids.get(&<&str as Into<String>>::into(uid.uid)))
        })
        .flatten()
}
