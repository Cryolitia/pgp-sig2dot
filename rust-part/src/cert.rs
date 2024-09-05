use crate::structure::{GraphNodeUid, OpenPgpUid};
use crate::KEY_SET_MAP;
use anyhow::{anyhow, Context};
use log::{info, warn};
use sequoia_net::KeyServer;
use sequoia_openpgp::{Cert, Fingerprint};
use std::collections::HashMap;
use std::default::Default;
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

fn fetch_cert_from_keyserver_recursive_internal(
    keyserver: &KeyServer,
    fingerprint: &Fingerprint,
    depth: u8,
    result: &mut HashMap<Fingerprint, Cert>,
) {
    if result.contains_key(fingerprint) {
        return;
    }
    info!("Gossiping key:\t{}\t\tdepth:\t{}", fingerprint, depth);
    match fetch_cert_from_keyserver(keyserver, fingerprint) {
        Ok(cert) => {
            result.insert(fingerprint.clone(), cert.clone());
            if depth > 0 {
                for uid in cert.userids() {
                    for sig in uid.signatures() {
                        sig.issuer_fingerprints().for_each(|fingerprint| {
                            fetch_cert_from_keyserver_recursive_internal(
                                keyserver,
                                fingerprint,
                                depth - 1,
                                result,
                            );
                        });
                    }
                }
            }
        }
        Err(err) => {
            warn!("{:#}", err)
        }
    }
}

pub(crate) fn fetch_cert_from_keyserver_recursive(
    keyserver: &KeyServer,
    fingerprints: &Vec<Fingerprint>,
    depth: u8,
) -> HashMap<Fingerprint, Cert> {
    let mut result = HashMap::new();
    for fingerprint in fingerprints {
        fetch_cert_from_keyserver_recursive_internal(keyserver, fingerprint, depth, &mut result);
    }
    result
}

pub(crate) fn fetch_cert_from_keyserver_once_lock_recursive(
    keyserver_lock: &OnceLock<KeyServer>,
    fingerprints: &Vec<Fingerprint>,
    depth: u8,
) -> HashMap<Fingerprint, Cert> {
    match keyserver_lock.get() {
        Some(keyserver) => fetch_cert_from_keyserver_recursive(keyserver, fingerprints, depth),
        None => Default::default(),
    }
}
