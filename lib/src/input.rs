use crate::helper::SuppressResultOk;
use anyhow::{Context, anyhow};
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::{Cert, Fingerprint};
use std::collections::HashMap;

pub fn parse_key_block(key_block: &[u8]) -> anyhow::Result<HashMap<Fingerprint, Cert>> {
    CertParser::from_bytes(key_block).map(|v| {
        v.filter_map(|r| {
            r.with_context(|| "While parsing cert...")
                .ok_or_warn("Invalid cert", |v| {
                    Ok::<(Fingerprint, Cert), String>((v.fingerprint(), v))
                })
        })
        .collect()
    })
}

pub fn parse_input_fingerprints(fingerprints: &[String]) -> Vec<Fingerprint> {
    fingerprints
        .iter()
        .filter_map(|v| {
            Fingerprint::from_hex(v.as_str())
                .with_context(|| format!("While parsing fingerprint: {v}"))
                .ok_or_warn("Invalid Fingerprint String:", |v| match v {
                    Fingerprint::Unknown {
                        version: _,
                        bytes: _,
                    } => Err(anyhow!("Unknown Fingerprint: {:?}", v)),
                    _ => Ok(v),
                })
        })
        .collect()
}
