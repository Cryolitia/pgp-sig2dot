use clap::Parser;
use clap_verbosity_flag::Verbosity;
use clio::Input;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub(crate) verbose: Verbosity,

    /// Import keyring from file or stdin
    #[arg(global = true, long, value_parser)]
    pub(crate) import: Option<Input>,

    /// Import keys from keyserver by fingerprint
    #[arg(global = true, long, value_parser, short = 'k', num_args = 1..)]
    pub(crate) fingerprint: Option<Vec<String>>,

    /// Show only primary UIDs
    #[arg(global = true, long, short = 'p')]
    pub(crate) show_primary_uid_only: bool,

    /// Show self-signatures
    #[arg(global = true, long, short = 'a')]
    pub(crate) show_self_sigs: bool,

    /// Fetch the newest signature from key server for each key in keyring
    #[arg(global = true, long)]
    pub(crate) online: bool,

    /// Keep the output simple instead of JSON object
    #[arg(global = true, long)]
    pub(crate) simple: bool,

    /// Key server
    #[arg(global = true, long, default_value = "hkps://keyserver.ubuntu.com")]
    pub(crate) keyserver: String,
}
