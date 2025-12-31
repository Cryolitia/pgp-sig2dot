use anyhow::Context;
use log::{debug, info, trace};
use pgp_sig2dot::github::{github_api, search_username_on_github};
use pgp_sig2dot::keyserver::{fetch_cert_from_keyservers, search_cert_from_keyservers};
use rnix::ast;
use rnix::ast::HasEntry;
use rnix::ast::InterpolPart::Literal;
use sequoia_openpgp::Cert;
use serde::Serialize;
use serialize_display_adapter_macro_derive::JsonSerializeDisplayAdapter;
use std::collections::HashMap;
use std::default::Default;

#[derive(Debug, Serialize, JsonSerializeDisplayAdapter)]
pub struct NixpkgsMaintainer {
    name: String,
    github: String,
    github_id: i64,
    email: Option<String>,
    keys: Vec<String>,
}

pub async fn parse_nixpkgs(
    client: &reqwest::Client,
) -> anyhow::Result<HashMap<String, NixpkgsMaintainer>> {
    let url = "https://raw.githubusercontent.com/NixOS/nixpkgs/refs/heads/master/maintainers/maintainer-list.nix";
    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| "While fetching Nixpkgs maintainer list")?;
    let body = response
        .text()
        .await
        .with_context(|| "While reading Nixpkgs maintainer list response body")?;
    let ast = rnix::Root::parse(&body).tree().expr().unwrap();

    let mut nixpkgs_maintainer_map: HashMap<String, NixpkgsMaintainer> = Default::default();

    if let ast::Expr::AttrSet(attr_set) = ast {
        for entry in attr_set.entries() {
            if let ast::Entry::AttrpathValue(attrpath_value) = entry {
                let handle = attrpath_value.attrpath().unwrap().to_string();
                let entry = attrpath_value.value().unwrap();

                let ast::Expr::AttrSet(attr_set_2) = entry else {
                    panic!();
                };

                let mut name: String = Default::default();
                let mut github: String = Default::default();
                let mut github_id: i64 = Default::default();
                let mut email: Option<String> = None;
                let mut keys: Vec<String> = Default::default();

                for entry2 in attr_set_2.entries() {
                    if let ast::Entry::AttrpathValue(attrpath_value2) = entry2 {
                        let handle2 = attrpath_value2.attrpath().unwrap().to_string();
                        let value2 = attrpath_value2.value().unwrap();
                        match handle2.as_str() {
                            "name" => {
                                let ast::Expr::Str(value3) = value2 else {
                                    panic!();
                                };
                                let Literal(literal) = value3.parts().next().unwrap() else {
                                    panic!();
                                };
                                name = literal.to_string();
                            }
                            "email" => {
                                let ast::Expr::Str(value3) = value2 else {
                                    panic!();
                                };
                                let Literal(literal) = value3.parts().next().unwrap() else {
                                    panic!();
                                };
                                email = Some(literal.to_string());
                            }
                            "github" => {
                                let ast::Expr::Str(value3) = value2 else {
                                    panic!();
                                };
                                let Literal(literal) = value3.parts().next().unwrap() else {
                                    panic!();
                                };
                                github = literal.to_string();
                            }
                            "githubId" => {
                                let ast::Expr::Literal(value3) = value2 else {
                                    panic!();
                                };
                                let ast::LiteralKind::Integer(integer) = value3.kind() else {
                                    panic!();
                                };
                                github_id = integer.value().unwrap();
                            }
                            "keys" => {
                                let ast::Expr::List(value3) = value2 else {
                                    panic!();
                                };
                                for item in value3.items() {
                                    if let ast::Expr::AttrSet(value4) = item {
                                        for entry3 in value4.entries() {
                                            if let ast::Entry::AttrpathValue(attrpath_value3) =
                                                entry3
                                            {
                                                let handle3 =
                                                    attrpath_value3.attrpath().unwrap().to_string();
                                                let value5 = attrpath_value3.value().unwrap();
                                                if handle3.as_str() == "fingerprint" {
                                                    let ast::Expr::Str(value6) = value5 else {
                                                        panic!();
                                                    };
                                                    let Literal(literal) =
                                                        value6.parts().next().unwrap()
                                                    else {
                                                        panic!();
                                                    };
                                                    keys.push(literal.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }

                let maintainer = NixpkgsMaintainer {
                    name,
                    github,
                    github_id,
                    email,
                    keys,
                };

                nixpkgs_maintainer_map.insert(handle.to_string(), maintainer);
            }
        }
    }

    trace!("{:#?}", nixpkgs_maintainer_map);

    Ok(nixpkgs_maintainer_map)
}

pub async fn fetch_cert_from_nixpkgs(
    client: &reqwest::Client,
    keyword: String,
    key_servers: &[String],
) -> anyhow::Result<Vec<anyhow::Result<Cert>>> {
    let map = parse_nixpkgs(client).await?;
    let mut certs: Vec<anyhow::Result<Cert>> = Default::default();

    for (handle, maintainer) in map.iter() {
        if handle == &keyword
            || maintainer.name == keyword
            || maintainer.email == Some(keyword.clone())
        {
            info!("Finding maintainer: {}", handle);
            debug!("maintainer: {:?}", maintainer);

            for key in maintainer.keys.iter() {
                match key.parse() {
                    Ok(key_handle) => {
                        let mut keyserver_certs =
                            fetch_cert_from_keyservers(key_servers, key_handle);
                        certs.append(&mut keyserver_certs);
                    }
                    Err(e) => {
                        certs.push(Err(anyhow::anyhow!(
                            "Failed to parse key handle from nixpkgs maintainer {}: {}",
                            handle,
                            e
                        )));
                    }
                }
            }

            if maintainer.email != Some(keyword.clone())
                && let Some(email) = maintainer.email.clone()
            {
                let mut email_certs = search_cert_from_keyservers(key_servers, email).await;
                certs.append(&mut email_certs);
            }

            let body = github_api(
                client,
                format!("https://api.github.com/user/{}", maintainer.github_id),
            )?;

            trace!("GitHub API response body: {}", body);

            let json: serde_json::Value = serde_json::from_str(&body)
                .with_context(|| "While parsing GitHub API response as JSON")?;

            if let Some(user) = json["login"].as_str() {
                info!("Found GitHub user {} by id {}", user, maintainer.github_id);
                let mut github_certs = search_username_on_github(client, user.to_string()).await?;
                certs.append(&mut github_certs);
            }
        }
    }
    Ok(certs)
}
