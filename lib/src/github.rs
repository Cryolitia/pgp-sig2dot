use crate::helper::SuppressErrors;
use anyhow::{Context, anyhow};
use clap::crate_version;
use log::{info, trace};
use reqwest::Client;
use sequoia_net::reqwest;
use sequoia_openpgp::Cert;
use sequoia_openpgp::parse::Parse;

pub async fn fetch_cert_from_github(
    reqwest_client: &reqwest::Client,
    input: &String,
) -> Result<Vec<anyhow::Result<Cert>>, anyhow::Error> {
    let mut author: Option<String> = async {
        let body = github_api(
            reqwest_client,
            format!(
                "https://api.github.com/search/commits?q=author-email:{}&per_page=1&page=0",
                input
            ),
        )?;

        trace!("GitHub API response body: {}", body);

        let json: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| "While parsing GitHub API response as JSON")?;

        json["total_count"].as_u64().inspect(|count_str| {
            info!(
                "GitHub search commits for email {} authored total count: {}",
                input, count_str
            )
        });

        let author = json["items"][0]["author"]["login"]
            .as_str()
            .ok_or_else(|| anyhow!("No author found for the given email"))?;

        Ok::<String, anyhow::Error>(author.to_string())
    }
    .await
    .or_warn("Searching Github");

    async {
        let body = github_api(
            reqwest_client,
            format!(
                "https://api.github.com/search/commits?q=committer-email:{}&per_page=1&page=0",
                input
            ),
        )?;

        trace!("GitHub API response body: {}", body);

        let json: serde_json::Value = serde_json::from_str(&body)
            .with_context(|| "While parsing GitHub API response as JSON")?;

        json["total_count"].as_u64().inspect(|count_str| {
            info!(
                "GitHub search commits for email {} committed total count: {}",
                input, count_str
            )
        });

        if author.is_none() {
            author = Some(
                json["items"][0]["committer"]["login"]
                    .as_str()
                    .ok_or_else(|| anyhow!("No user found for the given email"))?
                    .to_string(),
            );
        }

        Ok::<(), anyhow::Error>(())
    }
    .await
    .or_warn("Searching Github");

    if let Some(author) = author {
        info!("Found GitHub user: {}", author);
        search_username_on_github(reqwest_client, author).await
    } else {
        Err(anyhow!("No GitHub user found for the given email"))
    }
}

pub async fn search_username_on_github(
    reqwest_client: &Client,
    input: String,
) -> anyhow::Result<Vec<anyhow::Result<Cert>>> {
    async {
        let body = github_api(
            reqwest_client,
            format!("https://api.github.com/users/{}/gpg_keys", input),
        )?;

        trace!("GitHub GPG keys response body: {}", body);

        parse_github_gpg(body)
    }
    .await
    .with_context(|| format!("While fetching GPG keys from GitHub for user: {}", input))
}

pub fn github_api(reqwest_client: &reqwest::Client, url: String) -> anyhow::Result<String> {
    futures::executor::block_on(async {
        reqwest_client
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", format!("pgp-sig2dot/{}", crate_version!()))
            .send()
            .await?
            .text()
            .await
            .with_context(|| "While searching user email from GitHub API")
    })
}

pub fn parse_github_gpg(body: String) -> anyhow::Result<Vec<anyhow::Result<Cert>>> {
    let json: serde_json::Value = serde_json::from_str(body.as_str())
        .with_context(|| "While parsing GitHub GPG keys response as JSON")?;

    if let Some(keys) = json.as_array() {
        let mut certs: Vec<anyhow::Result<Cert>> = Vec::new();
        for key in keys {
            if let Some(armored_key) = key["raw_key"].as_str() {
                let cert = Cert::from_bytes(armored_key.as_bytes())
                    .with_context(|| "Parsing GitHub response");
                certs.push(cert);
            }
        }
        return Ok(certs);
    }

    Err(anyhow!("Not found valid GPG keys in GitHub response"))
}
