use clap::{Parser, Subcommand};
use clap_complete::Shell;
use clap_verbosity_flag::Verbosity;
use clio::{ClioPath, Input, Output};

#[derive(Parser, Debug, Clone)]
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

    /// Gossip the trust paths from the trust root(given above by `--fingerprint`), with an integer value which means the depth limit of gossiping
    /// Specially, 0 means no depth limit, it's only allowed without online mode
    #[arg(global = true, long, value_parser, num_args = 1..)]
    pub(crate) gossip: Option<u8>,

    /// Show only primary UIDs
    #[arg(global = true, long, short = 'p')]
    pub(crate) show_primary_uid_only: bool,

    /// Show self-signatures
    #[arg(global = true, long, short = 'a')]
    pub(crate) show_self_sigs: bool,

    /// Fetch the newest signature from key server for each key in keyring
    #[arg(global = true, long)]
    pub(crate) online: bool,

    /// Keep the output simple instead of JSON
    #[arg(global = true, long)]
    pub(crate) simple: bool,

    /// Key server
    #[arg(global = true, long, default_value = "hkps://keyserver.ubuntu.com")]
    pub(crate) keyserver: String,

    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum Commands {
    #[command(about = "Generate manual or shell auto complete file")]
    Gen {
        #[command(subcommand)]
        gen_command: GenCommand,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum GenCommand {
    #[command(about = "Generate manual file")]
    Man {
        #[arg(help = "Output Path", long)]
        path: ClioPath,
    },
    #[command(about = "Generate shell auto complete file")]
    Complete {
        args: Shell,
        #[arg(help = "Output Path", long, default_value = "-")]
        output: Output,
    },
}
