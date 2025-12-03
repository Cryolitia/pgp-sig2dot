use crate::cli::{Cli, Commands, DrawOptions, FetchSource, GenCommand, OutputType};
use crate::structure::graph_node_uid_fmt;
use crate::structure::open_pgp_sig_fmt;
use anyhow::{anyhow, Context};
use clap::{crate_version, CommandFactory, Parser};
use format::lazy_format;
use log::{debug, info, trace, warn};
use petgraph::algo::{has_path_connecting, DfsSpace};
use petgraph::dot::Dot;
use petgraph::graphmap::DiGraphMap;
use pgp_sig2dot::cert::build_key_set;
use pgp_sig2dot::get_pgp_uid_by_node_uid;
use pgp_sig2dot::helper::SuppressResultOk;
use pgp_sig2dot::helper::{SuppressErrors, SuppressPrint, SuppressResultErrors};
use pgp_sig2dot::input::{parse_input_fingerprints, parse_key_block};
use pgp_sig2dot::keyserver;
use pgp_sig2dot::structure::{GraphNodeUid, GraphNodeUidOwned, OpenPgpKey, OpenPgpSig, SigType};
use sequoia_net::{wkd, KeyServer};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::MarshalInto;
use sequoia_openpgp::{Cert, Fingerprint, KeyHandle};
use std::collections::{HashMap, HashSet};
use std::default::Default;
use std::fs::create_dir_all;
use std::hash::RandomState;
use std::io::Read;
use std::sync::{Arc, OnceLock};
use validator::validate_email;

mod cli;
mod structure;

static DRAW_OPTIONS: OnceLock<DrawOptions> = OnceLock::new();
static KEY_SET_MAP: OnceLock<HashMap<Arc<String>, OpenPgpKey>> = OnceLock::new();
static GOSSIP_LAYER_MAP: OnceLock<HashMap<Arc<String>, u8>> = OnceLock::new();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();
    let log_level = args.verbose.log_level_filter();
    env_logger::Builder::new().filter_level(log_level).init();
    debug!("Cli args: {args:?}");
    match args.command {
        Commands::Cli { gen_command } => {
            let cmd = Cli::command();
            match gen_command {
                GenCommand::ManGen { path } => {
                    let out_dir = path.to_path_buf();
                    debug!("man: generate to{out_dir:?}");
                    create_dir_all(&out_dir)?;
                    clap_mangen::generate_to(Cli::command(), out_dir)?;
                }
                GenCommand::Complete { args, mut output } => {
                    let name = cmd.get_display_name().unwrap_or_else(|| cmd.get_name());
                    clap_complete::generate(args, &mut Cli::command(), name, &mut output);
                }
            }
            Ok(())
        }
        Commands::Draw { draw_options } => {
            let keyserver: OnceLock<KeyServer> = OnceLock::new();

            keyserver
                .set(KeyServer::new(&draw_options.input.keyserver)?)
                .err();
            DRAW_OPTIONS.set(draw_options.clone()).unwrap();

            if draw_options.processor.gossip == Some(0) && draw_options.input.online {
                return Err(anyhow!("Online mode is not allowed with depth limit 0"));
            }

            let mut full_fingerprints: HashSet<Fingerprint> = Default::default();
            let mut certs: HashMap<Fingerprint, Cert> = Default::default();

            let args_import_is_none = draw_options.input.import.is_none();

            draw_options
                .input
                .import
                .map_and_warn_result("Importing key block", |mut input| {
                    let mut keyring: Vec<u8> = Default::default();
                    input
                        .read_to_end(&mut keyring)
                        .with_context(|| format!("While importing key block from {input}"))?;
                    certs.extend(parse_key_block(&keyring)?);
                    Ok::<(), anyhow::Error>(())
                });

            full_fingerprints.extend(
                certs
                    .keys()
                    .map(|v| v.to_owned())
                    .collect::<Vec<Fingerprint>>(),
            );

            let input_fingerprints: Vec<Fingerprint> = draw_options
                .fingerprint
                .as_deref()
                .map_or(Default::default(), parse_input_fingerprints);
            let input_trust_roots: HashSet<String> = draw_options
                .processor
                .trust_root
                .as_deref()
                .map_or(Default::default(), parse_input_fingerprints)
                .into_iter()
                .map(|v| v.to_string())
                .collect();

            full_fingerprints.extend(input_fingerprints.iter().cloned());

            if draw_options.input.online {
                full_fingerprints.iter().for_each(|fingerprint| {
                    keyserver::fetch_cert_from_keyserver_once_lock(&keyserver, fingerprint)
                        .with_context(|| {
                            format!("While fetching cert from keyserver: {fingerprint}")
                        })
                        .ok_or_warn("Failed to fetch cert from keyserver", |v| {
                            certs.insert(fingerprint.clone(), v);
                            Ok::<(), String>(())
                        });
                });
            }

            if draw_options.input.online
                && !input_fingerprints.is_empty()
                && draw_options.processor.gossip.is_some()
            {
                let gossip = draw_options.processor.gossip.unwrap_or(0);
                if gossip > 0 {
                    let mut result: HashMap<Fingerprint, Cert> = Default::default();
                    keyserver::fetch_cert_from_keyserver_once_lock_recursive(
                        &keyserver,
                        &input_fingerprints.iter().cloned().collect(),
                        gossip,
                        &mut result,
                    );
                    result.into_iter().for_each(|(fingerprint, cert)| {
                        certs.insert(fingerprint, cert);
                    });
                }
            }

            let filtered_certs: Vec<(Fingerprint, Cert)> = certs
                .into_iter()
                .filter(|(fingerprint, _)| {
                    if draw_options.processor.gossip.is_none()
                        && !args_import_is_none
                        && !input_fingerprints.is_empty()
                    {
                        input_fingerprints.contains(fingerprint)
                    } else {
                        true
                    }
                })
                .collect();

            let key_set = build_key_set(filtered_certs);

            if draw_options.processor.gossip.is_some() {
                let (key_set_filtered, gossip_layer_map) = pgp_sig2dot::gossip::build_gossip_layers(
                    draw_options.processor.gossip.unwrap_or(0),
                    &input_fingerprints,
                    key_set,
                );
                KEY_SET_MAP.set(key_set_filtered).unwrap();
                GOSSIP_LAYER_MAP.set(gossip_layer_map).unwrap();
            }

            let key_set = KEY_SET_MAP.get().unwrap();

            debug!(
                "{}",
                serde_json::to_string(&key_set).unwrap_or_else(|e| e.to_string())
            );

            let mut graph: DiGraphMap<GraphNodeUid, &OpenPgpSig> = DiGraphMap::new();

            key_set.iter().for_each(|(_, pgp_key)| {
                pgp_key.user_ids.iter().for_each(|(_, pgp_uid)| {
                    if !pgp_uid.is_primary && draw_options.show_primary_uid_only {
                        return;
                    }
                    graph.add_node(pgp_uid.into());
                });
            });

            key_set.iter().for_each(|(_, pgp_key)| {
                pgp_key.user_ids.iter().for_each(|(_, pgp_uid)| {
                    if !pgp_uid.is_primary && draw_options.show_primary_uid_only {
                        return;
                    }
                    pgp_uid.sig_vec.iter().for_each(|sig| {
                        key_set.get(&sig.fingerprint).inspect(|key_id| {
                            key_id
                                .user_ids
                                .get(&key_id.primary_user_id)
                                .inspect(|sig_uid| {
                                    if !draw_options.show_self_sigs && sig_uid.uid == pgp_uid.uid {
                                        return;
                                    }
                                    graph.add_edge(sig_uid.into(), pgp_uid.into(), sig);
                                });
                        });
                    });
                })
            });

            let nodes_to_remove: Vec<GraphNodeUidOwned>;
            let nodes_to_remove_2: Vec<GraphNodeUidOwned>;

            if draw_options.processor.trust_root.is_some() {
                let trust_roots: HashSet<GraphNodeUid> = graph
                    .nodes()
                    .filter(|node| input_trust_roots.contains(node.fingerprint))
                    .collect();
                let args_fingerprints_string: HashSet<String> =
                    input_fingerprints.iter().map(|v| v.to_string()).collect();
                let gossip_targets: HashSet<GraphNodeUid> = graph
                    .nodes()
                    .filter(|node| args_fingerprints_string.contains(node.fingerprint))
                    .collect();

                let mut graph_without_trust_roots: DiGraphMap<
                    GraphNodeUid,
                    &OpenPgpSig,
                    RandomState,
                > = graph.clone();
                trust_roots.iter().for_each(|root| {
                    graph_without_trust_roots.remove_node(*root);
                });

                let mut graph_without_targets: DiGraphMap<GraphNodeUid, &OpenPgpSig, RandomState> =
                    graph.clone();
                gossip_targets.iter().for_each(|target| {
                    graph_without_targets.remove_node(*target);
                });

                let mut space_without_trust_roots = DfsSpace::new(&graph_without_trust_roots);
                let mut space_without_targets = DfsSpace::new(&graph_without_targets);

                nodes_to_remove = graph
                    .nodes()
                    .filter(|node| {
                        if trust_roots.contains(node) || gossip_targets.contains(node) {
                            return false;
                        }
                        let mut has_from = false;
                        for root in trust_roots.iter() {
                            if has_path_connecting(
                                &graph_without_targets,
                                *root,
                                *node,
                                Some(&mut space_without_targets),
                            ) {
                                has_from = true;
                                debug!("Found path from {root:?} to {node:?}");
                                break;
                            }
                        }
                        if !has_from {
                            debug!("Remove node due to not from trust roots: {node:?}");
                            return true;
                        }
                        let mut has_to = false;
                        for target in gossip_targets.iter() {
                            if has_path_connecting(
                                &graph_without_trust_roots,
                                *node,
                                *target,
                                Some(&mut space_without_trust_roots),
                            ) {
                                has_to = true;
                                debug!("Found path from {node:?} to {target:?}");
                                break;
                            }
                        }
                        if !has_to {
                            debug!("Remove node due to not to targets: {node:?}");
                            return true;
                        }
                        false
                    })
                    .map(|node| GraphNodeUidOwned {
                        fingerprint: node.fingerprint.to_string(),
                        uid: node.uid.to_string(),
                    })
                    .collect();

                nodes_to_remove.iter().for_each(|node| {
                    graph.remove_node(node.into());
                });

                nodes_to_remove_2 = graph
                    .nodes()
                    .filter(|node| {
                        if !trust_roots.contains(node) && !gossip_targets.contains(node) {
                            return false;
                        }
                        if trust_roots.contains(node) {
                            let mut has_neighbor_outside = false;
                            for neighbor in graph.neighbors(*node) {
                                if !trust_roots.contains(&neighbor) {
                                    has_neighbor_outside = true;
                                    break;
                                }
                            }
                            if !has_neighbor_outside {
                                debug!(
                                    "Remove node due to no neighbor outside trust roots: {node:?}"
                                );
                                return true;
                            }
                        }
                        false
                    })
                    .map(|node| GraphNodeUidOwned {
                        fingerprint: node.fingerprint.to_string(),
                        uid: node.uid.to_string(),
                    })
                    .collect();

                nodes_to_remove_2.iter().for_each(|node| {
                    graph.remove_node(node.into());
                });
            }

            match draw_options.output.output_type {
                OutputType::Dot | OutputType::Metadata => {
                    let binding = &|_, (_, uid)| {
                        let mut attr = get_pgp_uid_by_node_uid(&KEY_SET_MAP, uid)
                            .map(|v| if v.is_revoked { " color = red " } else { "" })
                            .unwrap_or("")
                            .to_string();
                        if draw_options.processor.gossip.is_some() {
                            if let Some(map) = GOSSIP_LAYER_MAP.get() {
                                if let Some(layer) = map.get(&uid.fingerprint.to_string()) {
                                    if *layer == 0 {
                                        attr += " root = true ";
                                    }
                                }
                            }
                        }
                        attr
                    };

                    let dot = Dot::with_attr_getters(
                        &graph,
                        &[],
                        &|_, (_, _, sig)| {
                            (if sig.sig_type == SigType::Revoke {
                                " color = red "
                            } else {
                                ""
                            })
                            .to_string()
                        },
                        binding,
                    );

                    let content =
                        lazy_format!(|f| dot.graph_fmt(f, graph_node_uid_fmt, open_pgp_sig_fmt));
                    println!("{content}");
                }
                OutputType::KeyBlock => {
                    let certs = graph
                        .nodes()
                        .filter_map(|v| {
                            get_pgp_uid_by_node_uid(&KEY_SET_MAP, &v).map(|uid| {
                                (
                                    uid.original_cert.key_handle().to_hex(),
                                    uid.original_cert.clone(),
                                )
                            })
                        })
                        .collect::<HashMap<String, Arc<Cert>>>()
                        .values()
                        .map(|cert| Ok(cert.as_ref().clone()))
                        .collect::<Vec<Result<Cert, anyhow::Error>>>();
                    print_certs(Ok(certs));
                }
            }

            Ok(())
        }
        Commands::Fetch { fetch_options } => {
            let mut fetch_sources: HashSet<FetchSource> =
                fetch_options.from.iter().cloned().collect();
            if fetch_sources.contains(&FetchSource::All) {
                fetch_sources = vec![
                    FetchSource::Github,
                    FetchSource::KeyServer,
                    FetchSource::Wkd,
                ]
                .into_iter()
                .collect();
            };

            if fetch_sources.contains(&FetchSource::KeyServer) {
                let key_handle: Option<KeyHandle> = fetch_options
                    .input
                    .clone()
                    .parse()
                    .or_warn("Parsing key handle failed");

                for keyserver_addr in fetch_options.keyserver.iter() {
                    info!("Fetching from keyserver: {keyserver_addr}");
                    KeyServer::new(keyserver_addr).with_context(|| format!("While creating keyserver with address: {keyserver_addr}")).ok_or_warn("Fetch", |keyserver: KeyServer| {
                        futures::executor::block_on(async {
                            let result = if let Some(key_handle) = key_handle.clone() {
                                keyserver.get(key_handle).await.with_context(|| format!("While fetching by KeyHandle from keyserver: {keyserver_addr}"))
                            } else {
                                keyserver.search(fetch_options.input.clone()).await.with_context(|| format!("While searching by UserID from keyserver: {keyserver_addr}"))
                            };
                            print_certs(result);
                            Ok::<(), anyhow::Error>(())
                        })
                    });
                }
            }

            let reqwest_client = reqwest::Client::new();

            if validate_email(&fetch_options.input) {
                if fetch_sources.contains(&FetchSource::Wkd) {
                    info!("Input is a valid email, try fetching from Web Key Directory");

                    let certs = wkd::get(&reqwest_client, fetch_options.input.clone())
                        .await
                        .with_context(|| {
                            format!(
                                "While fetching from Web Key Directory for email: {}",
                                fetch_options.input
                            )
                        });
                    print_certs(certs);
                }

                if fetch_sources.contains(&FetchSource::Github) {
                    info!("Input is a valid email, try fetching from GitHub");

                    let mut author: Option<String> = async {
                        let body = github_api(&reqwest_client, format!("https://api.github.com/search/commits?q=author-email:{}&per_page=1&page=0", fetch_options.input))?;

                        trace!("GitHub API response body: {}", body);

                        let json: serde_json::Value = serde_json::from_str(&body)
                            .with_context(|| "While parsing GitHub API response as JSON")?;

                        json["total_count"].as_u64().inspect(|count_str| info!("GitHub search commits for email {} authored total count: {}", fetch_options.input, count_str));

                        let author = json["items"][0]["author"]["login"]
                            .as_str()
                            .ok_or_else(|| anyhow!("No author found for the given email"))?;

                        Ok::<String, anyhow::Error>(author.to_string())
                    }.await.or_warn("Searching Github");

                    async {
                            let body = github_api(&reqwest_client, format!("https://api.github.com/search/commits?q=committer-email:{}&per_page=1&page=0", fetch_options.input))?;

                            trace!("GitHub API response body: {}", body);

                            let json: serde_json::Value = serde_json::from_str(&body)
                                .with_context(|| "While parsing GitHub API response as JSON")?;

                            json["total_count"].as_u64().inspect(|count_str| info!("GitHub search commits for email {} committed total count: {}", fetch_options.input, count_str));

                        if author.is_none() {
                            author = Some(json["items"][0]["committer"]["login"]
                                .as_str()
                                .ok_or_else(|| anyhow!("No user found for the given email"))?.to_string());
                        }

                        Ok::<(), anyhow::Error>(())
                        }.await.or_warn("Searching Github");

                    if let Some(author) = author {
                        info!("Found GitHub user: {}", author);
                        async {
                            let body = github_api(
                                &reqwest_client,
                                format!("https://api.github.com/users/{}/gpg_keys", author),
                            )?;

                            trace!("GitHub GPG keys response body: {}", body);

                            parse_github_gpg(body)?;

                            Ok::<(), anyhow::Error>(())
                        }
                        .await
                        .with_context(|| {
                            format!("While fetching GPG keys from GitHub for user: {}", author)
                        })
                        .or_warn("Fetching GitHub");
                    }
                }
            } else {
                info!(
                    "Input is not a valid email, skip fetching from Web Key Directory, try searching from GitHub by username"
                );

                async {
                    let body = github_api(
                        &reqwest_client,
                        format!(
                            "https://api.github.com/users/{}/gpg_keys",
                            fetch_options.input
                        ),
                    )?;

                    trace!("GitHub GPG keys response body: {}", body);

                    parse_github_gpg(body)?;

                    Ok::<(), anyhow::Error>(())
                }
                .await
                .with_context(|| {
                    format!(
                        "While fetching GPG keys from GitHub for user: {}",
                        fetch_options.input
                    )
                })
                .or_warn("Fetching GitHub");
            }
            Ok(())
        }
    }
}

fn parse_github_gpg(body: String) -> Result<(), anyhow::Error> {
    let json: serde_json::Value = serde_json::from_str(body.as_str())
        .with_context(|| "While parsing GitHub GPG keys response as JSON")?;

    if let Some(keys) = json.as_array() {
        let mut certs: Vec<Result<Cert, anyhow::Error>> = Vec::new();
        for key in keys {
            if let Some(armored_key) = key["raw_key"].as_str() {
                let cert = Cert::from_bytes(armored_key.as_bytes())
                    .with_context(|| "Parsing GitHub response");
                certs.push(cert);
            }
        }
        print_certs(Ok(certs));
    }

    Ok(())
}

fn print_certs(certs: Result<Vec<Result<Cert, anyhow::Error>>, anyhow::Error>) {
    match certs {
        Ok(certs) => {
            for cert in certs {
                (|| -> anyhow::Result<String> {
                    Ok(String::from_utf8(cert?.armored().to_vec()?)?)
                })()
                .with_context(|| "While converting armored cert to string")
                .print_or_warn("");
            }
        }
        Err(e) => {
            warn!("{:#}", e);
        }
    }
}

fn github_api(reqwest_client: &reqwest::Client, url: String) -> Result<String, anyhow::Error> {
    futures::executor::block_on(async {
        reqwest_client
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .header(
                "User-Agent",
                format!("pgp-sig2dot-cli/{}", crate_version!()),
            )
            .send()
            .await?
            .text()
            .await
            .with_context(|| "While searching user email from GitHub API")
    })
}
