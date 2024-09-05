use crate::structure::{GraphNodeUid, OpenPgpUid, OpenPgpUidLayer};
use crate::{CLI_ARGS, KEY_SET_MAP};
use anyhow::{anyhow, Context};
use log::{info, warn};
use sequoia_net::KeyServer;
use sequoia_openpgp::{Cert, Fingerprint};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::default::Default;
use std::fmt::Formatter;
use std::sync::OnceLock;

pub(crate) fn get_pgp_uid_by_node_uid<'a>(uid: &'a GraphNodeUid) -> Option<&'a OpenPgpUid> {
    KEY_SET_MAP
        .get()
        .and_then(|v| {
            v.get(&uid.fingerprint.to_string())
                .map(|v| v.user_ids.get(&<&str as Into<String>>::into(uid.uid)))
        })
        .flatten()
}

pub(crate) fn simple_output<T>(object: &T, f: &mut Formatter<'_>, or: &String) -> std::fmt::Result
where
    T: Serialize,
{
    let simple_output = CLI_ARGS.get().map(|args| args.simple).unwrap_or(false);
    if !simple_output {
        write!(
            f,
            "{}",
            serde_json::to_string(object).unwrap_or_else(|e| format!("{}", e))
        )
    } else {
        write!(f, "{}", or)
    }
}

pub(crate) fn complex_output(
    object: &OpenPgpUid,
    f: &mut Formatter<'_>,
    or: &String,
) -> std::fmt::Result {
    let gossip_output = CLI_ARGS
        .get()
        .map(|args| args.gossip)
        .unwrap_or(None)
        .is_some();
    if gossip_output {
        simple_output(&<&OpenPgpUid as Into<OpenPgpUidLayer>>::into(object), f, or)
    } else {
        simple_output(object, f, or)
    }
}

pub(crate) fn fetch_cert_from_keyserver(
    keyserver: &KeyServer,
    fingerprint: &Fingerprint,
) -> anyhow::Result<Cert> {
    info!("Fetching key: {}", fingerprint);
    futures::executor::block_on(async {
        keyserver
            .get(fingerprint)
            .await
            .and_then(|v| {
                v.into_iter()
                    .next()
                    .ok_or(anyhow!("Key {} not found on keyserver", fingerprint))?
            })
            .with_context(|| format!("Failed to fetch key: {}", fingerprint))
    })
}

pub(crate) fn fetch_cert_from_keyserver_once_lock(
    keyserver_lock: &OnceLock<KeyServer>,
    fingerprint: &Fingerprint,
) -> anyhow::Result<Cert> {
    match keyserver_lock.get() {
        Some(keyserver) => fetch_cert_from_keyserver(keyserver, fingerprint),
        None => Err(anyhow!("Keyserver is not initialized")),
    }
}

pub(crate) fn fetch_cert_from_keyserver_recursive(
    keyserver: &KeyServer,
    search: &HashSet<Fingerprint>,
    depth: u8,
    result: &mut HashMap<Fingerprint, Cert>,
) {
    let mut search_next_layer: HashSet<Fingerprint> = Default::default();
    for fingerprint in search {
        info!("Gossiping key:\t{}\t\tdepth:\t{}", fingerprint, depth);
        if result.contains_key(fingerprint) {
            continue;
        }
        match fetch_cert_from_keyserver(keyserver, fingerprint) {
            Ok(cert) => {
                result.insert(fingerprint.clone(), cert.clone());
                if depth > 0 {
                    for uid in cert.userids() {
                        for sig in uid.signatures() {
                            search_next_layer.extend(sig.issuer_fingerprints().cloned());
                        }
                    }
                }
            }
            Err(err) => {
                warn!("{:#}", err)
            }
        }
    }
    if depth > 0 {
        fetch_cert_from_keyserver_recursive(keyserver, &search_next_layer, depth - 1, result);
    }
}

pub(crate) fn fetch_cert_from_keyserver_once_lock_recursive(
    keyserver_lock: &OnceLock<KeyServer>,
    search: &HashSet<Fingerprint>,
    depth: u8,
    result: &mut HashMap<Fingerprint, Cert>,
) {
    match keyserver_lock.get() {
        Some(keyserver) => fetch_cert_from_keyserver_recursive(keyserver, search, depth, result),
        None => Default::default(),
    }
}
