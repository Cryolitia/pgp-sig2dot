use crate::structure::OpenPgpKey;
use sequoia_openpgp::Fingerprint;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub fn build_gossip_layers(
    depth: u8,
    input_fingerprints: &[Fingerprint],
    key_set: HashMap<Arc<String>, OpenPgpKey>,
) -> (HashMap<Arc<String>, OpenPgpKey>, HashMap<Arc<String>, u8>) {
    let mut gossip_layers: HashMap<u8, HashSet<Arc<String>>> = Default::default();
    let mut gossip_layer_map: HashMap<Arc<String>, u8> = Default::default();

    let mut layer: HashSet<Arc<String>> = Default::default();
    input_fingerprints.iter().for_each(|fingerprint| {
        let fingerprint: Arc<String> = fingerprint.to_string().into();
        layer.insert(fingerprint.clone());
        gossip_layer_map.insert(fingerprint, 0);
    });
    gossip_layers.insert(0, layer);

    let mut i: u8 = 0;

    while let Some(last_layer) = gossip_layers.get(&i) {
        if last_layer.is_empty() {
            break;
        }
        i += 1;

        let mut layer: HashSet<Arc<String>> = Default::default();
        last_layer.iter().for_each(|fingerprint| {
            key_set.get(fingerprint).inspect(|cert| {
                cert.user_ids.iter().for_each(|(_, pgp_uid)| {
                    pgp_uid.sig_vec.iter().for_each(|sig| {
                        if !gossip_layer_map.contains_key(&sig.fingerprint) {
                            layer.insert(sig.fingerprint.clone().into());
                            gossip_layer_map.insert(sig.fingerprint.clone().into(), i);
                        }
                    })
                })
            });
        });

        if layer.is_empty() {
            break;
        }
        gossip_layers.insert(i, layer);
    }

    let key_set = key_set
        .into_iter()
        .filter_map(|(fingerprint, pgp_key)| {
            if let Some(layer) = gossip_layer_map.get(&fingerprint) {
                let gossip = depth;
                if gossip == 0 || layer <= &gossip {
                    Some((fingerprint, pgp_key))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    (key_set, gossip_layer_map)
}
