use crate::helper::{SuppressErrors, SuppressResultOk, SuppressResultOkOrDefault};
use crate::structure::{OpenPgpKey, OpenPgpSig, OpenPgpUid};
use anyhow::{anyhow, Context};
use log::{debug, trace, warn};
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::{Cert, Fingerprint};
use sequoia_wot::{CertSynopsis, RevocationStatus, UserIDSynopsis};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn build_key_set(certs: Vec<(Fingerprint, Cert)>) -> HashMap<Arc<String>, OpenPgpKey> {
    let policy = StandardPolicy::new();
    certs.into_iter().filter_map(|(_, original_cert)| {
            original_cert.with_policy(&policy, SystemTime::now())
                .with_context(|| anyhow!("While checking cert policy {}", original_cert))
                .ok_or_warn(
                    "Error while checking cert policy",
                    |cert| {
                        let cert_synopsis: CertSynopsis = cert.clone().into();
                        let id = Arc::new(cert_synopsis.fingerprint().to_string());
                        let primary_id = Arc::new(cert.primary_userid().map(|v| v.userid().to_string()).unwrap_or_default());
                        let original_cert = Arc::new(original_cert.clone());
                        Ok::<(Arc<String>, OpenPgpKey), String>((
                            id.clone(),
                            OpenPgpKey {
                                id: id.clone(),
                                is_revoked: cert_synopsis.revocation_status()
                                    != RevocationStatus::NotAsFarAsWeKnow,
                                is_expired: cert_synopsis
                                    .expiration_time()
                                    .map_or_else(|| false, |v| v < SystemTime::now()),
                                user_ids: cert
                                    .userids()
                                    .map(|user_id| {
                                        let user_id_synopsis: UserIDSynopsis =
                                            user_id.clone().into();
                                        trace!("{user_id:#?}");
                                        let uid = Arc::new(user_id.userid().to_string());
                                        (uid.clone(), OpenPgpUid {
                                            fingerprint: id.clone(),
                                            uid: uid.clone(),
                                            name: user_id.userid().name()
                                                .with_context(|| anyhow!("While getting user ID name: {:?}", user_id))
                                                .ok_or_warn_default(
                                                    "Invalid Name",
                                                    |v: &str| Ok::<String, String>(v.to_string())
                                                ),
                                            email: user_id.userid().email()
                                                .with_context(|| anyhow!("While getting user ID email: {:?}", user_id))
                                                .ok_or_warn_default(
                                                    "Invalid Email",
                                                    |v: &str| Ok::<String, String>(v.to_string())
                                                ),
                                            comment: user_id.userid().comment()
                                                .with_context(|| anyhow!("While getting user ID comment: {:?}", user_id))
                                                .ok_or_warn_default(
                                                    "Invalid Comment",
                                                    |v: &str| Ok::<String, String>(v.to_string())
                                                ),
                                            sig_vec: user_id
                                                .signatures()
                                                .filter_map(|sig| {
                                                    Some(OpenPgpSig {
                                                        fingerprint: find_fingerprint_in_sig(sig),
                                                        uid: sig.signers_user_id().map_or_else(|| {
                                                            "".to_string()
                                                        }, |v| String::from_utf8(Vec::from(v)).unwrap_or_else(|e| {
                                                            warn!("Invalid Signer User ID: {:#}", e);
                                                            "".to_string()
                                                        })),
                                                        trust_level: sig.trust_signature().unwrap_or((0, 0)).0,
                                                        trust_value: sig.trust_signature().unwrap_or((0, 0)).1.into(),
                                                        sig_type: sig.typ().into(),
                                                        creation_time: sig.signature_creation_time()?.duration_since(UNIX_EPOCH).ok()?.as_secs(),
                                                    })
                                                })
                                                .collect(),
                                            is_revoked: user_id_synopsis.revocation_status()
                                                != RevocationStatus::NotAsFarAsWeKnow,
                                            is_primary: user_id.userid().to_string() == *primary_id,
                                            original_cert: original_cert.clone(),
                                        })
                                    })
                                    .collect(),
                                primary_user_id: primary_id.clone(),
                                original_cert: original_cert.clone(),
                            },
                        ))
                    },
                )
        })
        .collect()
}

fn find_fingerprint_in_sig(sig: &Signature) -> String {
    let mut sig = sig.clone();
    let fingerprint = sig.issuer_fingerprints().next();
    match fingerprint {
        Some(fingerprint) => fingerprint.to_string(),
        None => {
            debug!(
                "No issuer fingerprint found in signature {sig:?} , trying to add missing issuers..."
            );
            sig.add_missing_issuers()
                .map_or_warn("Failed to add missing issuers", |()| {});
            let fingerprint = sig.issuer_fingerprints().next();
            fingerprint.ok_or_warn_default(
                &format!("Cannot find fingerprint in signature: {sig:?}"),
                |v| Ok::<String, String>(v.to_string()),
            )
        }
    }
}

pub fn insert_or_update_cert(certs: &mut HashMap<Fingerprint, Cert>, new_cert: Cert) {
    let fingerprint = new_cert.fingerprint();
    match certs.get(&fingerprint) {
        Some(existing_cert) => {
            debug!("Updating cert with fingerprint {}", fingerprint);
            existing_cert
                .clone()
                .merge_public(new_cert)
                .with_context(|| format!("While merging cert for {}", existing_cert.fingerprint()))
                .ok_or_warn("merge cert", |cert| {
                    certs.insert(fingerprint, cert);
                    Ok::<(), anyhow::Error>(())
                });
        }
        None => {
            debug!("Inserting new cert with fingerprint {}", fingerprint);
            certs.insert(fingerprint, new_cert);
        }
    }
}
