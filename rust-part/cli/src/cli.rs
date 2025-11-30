use clap::{ArgGroup, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use clap_verbosity_flag::Verbosity;
use clio::ClioPath;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub(crate) command: Commands,

    #[command(flatten)]
    pub(crate) verbose: Verbosity,
}

#[derive(clap::Args, Debug, Clone, Default)]
#[command(next_help_heading = "Input")]
#[clap(group(
            ArgGroup::new("input")
                .required(true)
                .args(&["import", "online"])
                .multiple(true),
))]
pub struct Input {
    /// Import OpenPGP key set from file or stdin
    ///
    /// Use `--import -` to read from stdin
    #[clap(group = "input")]
    #[arg(short = 'i', long, value_parser, value_name = "PATH")]
    pub(crate) import: Option<clio::Input>,

    /// Fetch the newest keys from key server
    #[clap(group = "input")]
    #[arg(long)]
    pub(crate) online: bool,

    /// Key server address
    #[arg(
        global = true,
        long,
        requires = "online",
        default_value = "hkps://keyserver.ubuntu.com"
    )]
    pub(crate) keyserver: String,
}

/// _TODO_
#[derive(Debug, Clone, Default, ValueEnum, PartialEq)]
#[clap(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum OutputType {
    #[default]
    Dot,
    /// DOT format with metadata in JSON format in label
    Metadata,
    /// OpenPGP key block format can be imported to GnuPG, etc.
    KeyBlock,
    Svg,
}

/// _TODO_
#[derive(Debug, Clone, Default, ValueEnum, PartialEq)]
pub(crate) enum OutputLayout {
    /// Choose the default layout algorithm
    #[default]
    Default,
    /// Nodes are placed on concentric circles
    Twopi,
    /// Force-directed graph drawing algorithm
    Fdp,
}

#[derive(clap::Args, Debug, Clone, Default)]
#[command(next_help_heading = "Output")]
#[clap(group(
            ArgGroup::new("output")
                .required(false)
                .args(&["output_type", "output_layout"])
                .multiple(true),
))]
pub struct Output {
    /// The output format
    #[clap(group = "output")]
    #[arg(short = 't', long = "type", default_value = "DOT")]
    pub(crate) output_type: OutputType,

    /// The layout algorithms to use, may be ignored under certain conditions
    #[clap(group = "output")]
    #[arg(long = "layout", default_value = "default")]
    pub(crate) output_layout: OutputLayout,
}

#[derive(clap::Args, Debug, Clone, Default)]
#[command(next_help_heading = "Processor")]
#[clap(group(
            ArgGroup::new("processor")
                .required(false)
                .args(&["gossip", "trust_root"])
                .multiple(true),
))]
pub struct Processor {
    /// Gossip the trust paths to the targets (given above by `--fingerprint`), with an integer value which means the depth limit of gossiping
    ///
    /// Specially, 0 means no depth limit, and it's only allowed without online mode enabled
    #[clap(group = "processor")]
    #[arg(global = true, long, value_parser, num_args = 1..)]
    pub(crate) gossip: Option<u8>,

    /// Set the trust roots in the gossip mode
    ///
    /// Only User IDs that have a trust path from the trust roots and to the target will remain
    #[clap(group = "processor")]
    #[arg(global = true, long, value_parser, num_args = 1.., requires = "gossip", value_name = "FINGERPRINT")]
    pub(crate) trust_root: Option<Vec<String>>,
}

#[derive(clap::Args, Debug, Clone, Default)]
pub(crate) struct DrawOptions {
    /// Include only primary UIDs
    #[arg(global = true, long, short = 'p')]
    pub(crate) show_primary_uid_only: bool,

    /// Include self-signatures
    #[arg(global = true, long)]
    pub(crate) show_self_sigs: bool,

    /// Specific keys by fingerprint
    ///
    /// The using of Key ID is prohibited because of the collision
    #[arg(long, value_parser, short = 'k', num_args = 1..)]
    pub(crate) fingerprint: Option<Vec<String>>,

    #[command(flatten)]
    pub(crate) input: Input,

    #[command(flatten)]
    pub(crate) processor: Processor,

    #[command(flatten)]
    pub(crate) output: Output,
}

#[derive(Debug, Clone, Default, ValueEnum, Eq, Hash, PartialEq)]
pub(crate) enum FetchSource {
    /// Fetch from key servers
    KeyServer,
    /// Fetch from Web Key Directory
    Wkd,
    /// Fetch from GitHub
    Github,
    /// All
    #[default]
    All,
}

#[derive(clap::Args, Debug, Clone, Default)]
pub(crate) struct FetchOptions {
    /// Input string as keyword to search keys
    pub(crate) input: String,
    /// Key server addresses
    #[arg(long, value_parser, default_value = "hkps://keyserver.ubuntu.com", num_args = 0..)]
    pub(crate) keyserver: Vec<String>,
    /// Sources to fetch keys from
    #[arg(long, num_args = 1.., default_value = "all", value_parser)]
    pub(crate) from: Vec<FetchSource>,
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum Commands {
    #[command(about = "Generate Cli manual or shell auto complete file")]
    Cli {
        #[command(subcommand)]
        gen_command: GenCommand,
    },
    #[command(about = "Draw the trust graph")]
    Draw {
        #[command(flatten)]
        draw_options: DrawOptions,
    },
    #[command(
        about = "Fetch keys from the Internet by multiple sources",
        long_about = "Available sources including: KeyServer, Web Key Directory, GitHub"
    )]
    Fetch {
        #[command(flatten)]
        fetch_options: FetchOptions,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum GenCommand {
    #[command(about = "Generate manual file")]
    ManGen {
        #[arg(help = "Output Path", long)]
        path: ClioPath,
    },
    #[command(about = "Generate shell auto complete file")]
    Complete {
        args: Shell,
        #[arg(help = "Output Path", long, default_value = "-")]
        output: clio::Output,
    },
}
