use crate::helper::SuppressErrors;
use anyhow::{anyhow, Context};
use log::{info, trace};
use sequoia_net::KeyServer;
use sequoia_openpgp::{Cert, Fingerprint};
use std::collections::{HashMap, HashSet};
use std::default::Default;
use std::sync::OnceLock;

pub(crate) fn fetch_cert_from_keyserver(
    keyserver: &KeyServer,
    fingerprint: &Fingerprint,
) -> anyhow::Result<Cert> {
    info!("Fetching key: {fingerprint}");
    futures::executor::block_on(async {
        keyserver
            .get(fingerprint)
            .await
            .and_then(|v| {
                v.into_iter()
                    .next()
                    .ok_or(anyhow!("Key {} not found on keyserver", fingerprint))?
            })
            .with_context(|| format!("Failed to fetch key: {fingerprint}"))
    })
}

pub fn fetch_cert_from_keyserver_once_lock(
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
    info!("Gossiping on depth:\t{},\t\tkeys:\t{}", depth, search.len());
    let mut search_next_layer: HashSet<Fingerprint> = Default::default();
    for fingerprint in search {
        trace!("Gossiping key:\t{fingerprint}\t\tdepth:\t{depth}");
        if result.contains_key(fingerprint) {
            continue;
        }
        fetch_cert_from_keyserver(keyserver, fingerprint)
            .with_context(|| format!("Gossiping key:\t{fingerprint}"))
            .map_or_warn("Failed to fetch cert from keyserver", |cert| {
                result.insert(fingerprint.clone(), cert.clone());
                let mut issuers: HashSet<Fingerprint> = Default::default();
                for uid in cert.userids() {
                    for sig in uid.signatures() {
                        let mut sig = sig.clone();
                        trace!("{sig:#?}");
                        if sig.issuer_fingerprints().collect::<Vec<_>>().is_empty() {
                            info!("No issuer fingerprint found in signature {sig:?} , trying to add missing issuers...");
                            sig.add_missing_issuers().map_or_warn("Failed to add missing issuers", |()|{});
                        }
                        issuers.extend(sig.issuer_fingerprints().cloned());
                    }
                }
                info!(
                    "Gossiping key:\t{}\t\tissuers:\t{}\tdepth:\t{}",
                    fingerprint,
                    issuers.len(),
                    depth
                );
                if depth > 0 {
                    search_next_layer.extend(issuers);
                }
            })
    }
    if depth > 0 {
        fetch_cert_from_keyserver_recursive(keyserver, &search_next_layer, depth - 1, result);
    }
}

pub fn fetch_cert_from_keyserver_once_lock_recursive(
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
