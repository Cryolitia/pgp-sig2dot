use crate::cert::get_pgp_uid_by_node_uid;
use crate::cli::{Cli, Commands, GenCommand};
use crate::structure::{GraphNodeUid, OpenPgpKey, OpenPgpSig, OpenPgpUid, SigType};
use anyhow::anyhow;
use clap::{CommandFactory, Parser};
use log::{debug, error, trace, warn};
use petgraph::dot::Dot;
use petgraph::graphmap::DiGraphMap;
use sequoia_net::KeyServer;
use sequoia_openpgp::cert::CertParser;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::{Cert, Fingerprint};
use sequoia_wot::{CertSynopsis, RevocationStatus, UserIDSynopsis};
use std::collections::{HashMap, HashSet};
use std::default::Default;
use std::fs::create_dir_all;
use std::io::{Error, Read};
use std::process::exit;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

mod cert;
mod cli;
mod structure;

static KEY_SET_MAP: OnceLock<HashMap<Arc<String>, OpenPgpKey>> = OnceLock::new();
static SIMPLE_OUTPUT: OnceLock<bool> = OnceLock::new();

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    let policy = StandardPolicy::new();
    let log_level = args.verbose.log_level_filter();
    env_logger::Builder::new().filter_level(log_level).init();
    debug!("Cli args: {:?}", args);

    if let Some(command) = args.command {
        match command {
            Commands::Gen { gen_command } => {
                (|| -> anyhow::Result<()> {
                    let cmd = Cli::command();
                    match gen_command {
                        GenCommand::Man { path } => {
                            let out_dir = path.to_path_buf();
                            debug!("man: generate to{:?}", out_dir);
                            create_dir_all(&out_dir)?;
                            clap_mangen::generate_to(Cli::command(), out_dir)?;
                        }
                        GenCommand::Complete { args, mut output } => {
                            let name = cmd.get_display_name().unwrap_or_else(|| cmd.get_name());
                            clap_complete::generate(args, &mut Cli::command(), name, &mut output);
                        }
                    }
                    Ok(())
                })()
                .err()
                .inspect(|e| {
                    error!("{:#}", e);
                    exit(1);
                });
                exit(0);
            }
        }
    }

    (|| -> anyhow::Result<()> {
        let keyserver: OnceLock<KeyServer> = OnceLock::new();

        keyserver.set(KeyServer::new(&args.keyserver)?).err();
        SIMPLE_OUTPUT.set(args.simple).unwrap();

        if args.gossip == Some(0) && args.online {
            return Err(anyhow!("Online mode is not allowed with depth limit 0"));
        }

        if args.import.is_none() && args.fingerprint.is_none() {
            return Err(anyhow!("No input found, please consider provide at least one of keyring or fingerprint."));
        }

        if args.fingerprint.is_some() && args.import.is_none() && !args.online {
            return Err(anyhow!("Offline mode is not allowed without keyring"));
        }

        let mut fingerprints: HashSet<Fingerprint> = Default::default();
        let mut certs: HashMap<Fingerprint, Cert> = Default::default();

        let args_import_is_none = args.import.is_none();

        args.import.map_or(Ok(()),
                           |mut input| {
                               let mut keyring: Vec<u8> = Default::default();
                               input.read_to_end(&mut keyring)?;
                               CertParser::from_bytes(&keyring).map_or_else(
                                   |e| warn!("{}" ,e),
                                   |v| {
                                       v.for_each(|r| {
                                           r.map_or_else(
                                               |e| {
                                                   warn!("Invalid Cert: {}", e);
                                               },
                                               |v| {
                                                   if args.online {
                                                       fingerprints.insert(v.fingerprint());
                                                   }
                                                   certs.insert(v.fingerprint(), v);
                                               },
                                           )
                                       });
                                   },
                               );
                               Ok(())
                           },
        ).err().inspect(|e: &Error| {
            warn!("{}", e);
        });

        let args_fingerprints: Vec<Fingerprint> = args.fingerprint.map_or(Default::default(),|v| {
            v.into_iter().filter_map(|v| {
                Fingerprint::from_hex(v.as_str()).map_or_else(|e| {
                    warn!("Invalid Fingerprint: {}", e);
                    None
                }, |v| {
                   Some(v)
                })
            }).collect()
        });

        fingerprints.extend(args_fingerprints.iter().cloned());

        if args.online {
            fingerprints.iter().for_each(|fingerprint| {
                match cert::fetch_cert_from_keyserver_once_lock(&keyserver, fingerprint) {
                    Ok(cert) => { certs.insert(fingerprint.clone(), cert); }
                    Err(e) => { warn!("{:#}", e) }
                };
            });
        }

        if args.online && !args_fingerprints.is_empty() && args.gossip.is_some() {
            let gossip = args.gossip.unwrap_or(0);
            if gossip > 0 {
                cert::fetch_cert_from_keyserver_once_lock_recursive(&keyserver, &args_fingerprints, gossip)
                    .into_iter()
                    .for_each(|(fingerprint, cert)| {
                        certs.insert(fingerprint, cert);
                    });
            }
        }

        trace!("{:?}", certs);

        let key_set: HashMap<Arc<String>, OpenPgpKey> = certs
            .iter()
            .filter(|cert| {
                if args.gossip.is_none() && !args_import_is_none && !args_fingerprints.is_empty() {
                    args_fingerprints.contains(cert.0)
                } else {
                    true
                }
            })
            .filter_map(|cert| {
                cert.1.with_policy(&policy, SystemTime::now())
                    .map_err(|e| error!("{}", e))
                    .map_or_else(
                        |_| None,
                        |cert| {
                            let cert_synopsis: CertSynopsis = cert.clone().into();
                            let id = Arc::new(cert_synopsis.fingerprint().to_string());
                            let primary_id = Arc::new(cert.primary_userid().map(|v| v.userid().to_string()).unwrap_or_default());
                            Some((
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
                                            let uid = Arc::new(user_id.to_string());
                                            (uid.clone(), OpenPgpUid {
                                                fingerprint: id.clone(),
                                                uid: uid.clone(),
                                                name: user_id.name2().map_or_else(
                                                    |e| {
                                                        warn!("Invalid Name: {}", e);
                                                        "".to_string()
                                                    },
                                                    |v| {
                                                        v.map_or_else(
                                                            || "".to_string(),
                                                            |v| v.to_string(),
                                                        )
                                                    },
                                                ),
                                                email: user_id.email2().map_or_else(
                                                    |e| {
                                                        warn!("Invalid Email: {}", e);
                                                        "".to_string()
                                                    },
                                                    |v| {
                                                        v.map_or_else(
                                                            || "".to_string(),
                                                            |v| v.to_string(),
                                                        )
                                                    },
                                                ),
                                                comment: user_id.comment2().map_or_else(
                                                    |e| {
                                                        warn!("Invalid Comment: {}", e);
                                                        "".to_string()
                                                    },
                                                    |v| {
                                                        v.map_or_else(
                                                            || "".to_string(),
                                                            |v| v.to_string(),
                                                        )
                                                    },
                                                ),
                                                sig_vec: user_id
                                                    .signatures()
                                                    .filter_map(|sig| {
                                                        Some(OpenPgpSig {
                                                            fingerprint: sig.issuer_fingerprints().next().map_or_else(|| {
                                                                warn!("Invalid Issuer: {:?}", sig);
                                                                "".to_string()
                                                            }, |v| v.to_string()),
                                                            uid: sig.signers_user_id().map_or_else(|| {
                                                                "".to_string()
                                                            }, |v| String::from_utf8(Vec::from(v)).unwrap_or_else(|e| {
                                                                warn!("Invalid Signer User ID: {}", e);
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
                                            })
                                        })
                                        .collect(),
                                    primary_user_id: primary_id.clone(),
                                },
                            ))
                        },
                    )
            })
            .collect();

        KEY_SET_MAP.set(key_set.clone()).unwrap();

        debug!(
            "{}",
            serde_json::to_string(&key_set).unwrap_or_else(|e| e.to_string())
        );

        let mut graph: DiGraphMap<GraphNodeUid, &OpenPgpSig> = DiGraphMap::new();

        key_set.iter().for_each(|pair| {
            pair.1.user_ids.iter().for_each(|pair| {
                if !pair.1.is_primary && args.show_primary_uid_only {
                    return;
                }
                graph.add_node(pair.1.into());
            });
        });

        key_set.iter().for_each(|pair| {
            pair.1.user_ids.iter().for_each(|uid| {
                if !uid.1.is_primary && args.show_primary_uid_only {
                    return;
                }
                uid.1.sig_vec.iter().for_each(|sig| {
                    key_set.get(&sig.fingerprint).inspect(|key_id| {
                        key_id.user_ids.get(&key_id.primary_user_id).inspect(|sig_uid| {
                            if !args.show_self_sigs && sig_uid.uid == uid.1.uid {
                                return;
                            }
                            graph.add_edge(sig_uid.into(), uid.1.into(), sig);
                        });
                    });
                });
            })
        });

        let dot = Dot::with_attr_getters(&graph, &[], &|_, v|
            (if v.2.sig_type == SigType::Revoke { "color=red" } else { "" }).to_string(), &|_, v| {
            get_pgp_uid_by_node_uid(v.1).map(|v| {
                if v.is_revoked { "color=red" } else { "" }
            }).unwrap_or("").to_string()
        },
        );
        let content = format!("{}", dot);
        println!("{}", content);

        Ok(())
    })()
        .map_or_else(
            |e| -> i32 {
                error!("{:#}", e);
                exit(1)
            },
            |_| exit(0),
        );
}
