//! OAIE CLI entry point.
//!
//! Parses subcommands via clap, initializes logging, and dispatches to handlers.

mod commands;
mod output;

use clap::{CommandFactory, Parser, Subcommand};

/// Build a long version string including git hash and build date.
fn long_version() -> &'static str {
    // Leak a small string — called once at startup.
    let s = format!(
        "{}\ngit:    {}\nbuilt:  {}\ntarget: {}",
        env!("CARGO_PKG_VERSION"),
        env!("OAIE_GIT_HASH"),
        env!("OAIE_BUILD_DATE"),
        option_env!("OAIE_TARGET").unwrap_or("unknown"),
    );
    Box::leak(s.into_boxed_str())
}

#[derive(Parser)]
#[command(
    name = "oaie",
    version,
    long_version = long_version(),
    help_template = concat!(
        "  ___    _    ___ _____\n",
        " / _ \\  / \\  |_ _| ____|   OAIE v", env!("CARGO_PKG_VERSION"), "\n",
        "| | | |/ _ \\  | ||  _|     Observed & Attested\n",
        "| |_| / ___ \\ | || |___    Isolated Execution\n",
        " \\___/_/   \\_\\___|_____|\n",
        "\n{usage-heading} {usage}\n\n{all-args}\n\nhttps://oaie.run\n",
    )
)]
struct Cli {
    /// Suppress all OAIE output; only the sandboxed command's own output is shown
    #[arg(short, long, global = true)]
    quiet: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a command in an isolated, observed environment
    Run(Box<commands::run::RunCmd>),

    /// Dump a run's artifact (stdout, stderr, manifest, …) to stdout
    Cat(commands::cat::CatCmd),

    /// Validate a job spec against a policy without running it
    Check(commands::check::CheckCmd),

    /// Inspect a completed run's artifacts and metadata
    Inspect(commands::inspect::InspectCmd),

    /// List past runs with their status and metadata
    List(commands::list::ListCmd),

    /// Print the stored REPORT.md for a completed run
    Report(commands::report::ReportCmd),

    /// Verify the integrity of a run's artifacts
    Verify(commands::verify::VerifyCmd),

    /// Replay a previous run
    Replay(commands::replay::ReplayCmd),

    /// Compare two past runs side-by-side
    Diff(commands::diff::DiffCmd),

    /// Package a run into a self-contained .tar.gz archive for sharing
    Export(commands::export::ExportCmd),

    /// Remove old runs and unreferenced blobs from the store
    Clean(commands::clean::CleanCmd),

    /// Initialize the OAIE store
    Init(commands::init::InitCmd),

    /// Check system requirements and installation health
    Doctor(commands::doctor::DoctorCmd),

    /// Inspect named policy presets
    #[command(subcommand)]
    Policy(commands::policy::PolicyCmd),

    /// Manage Firecracker microVM backend
    #[command(subcommand)]
    Firecracker(commands::firecracker::FirecrackerCmd),

    /// Manage signing keys for manifest attestation
    #[command(subcommand)]
    Key(commands::key::KeyCmd),

    /// Manage agent sessions (persistent sandboxes with tool dispatch)
    #[command(subcommand)]
    Session(commands::session::SessionCmd),

    /// Interact with the content-addressed store
    #[command(subcommand)]
    Cas(commands::cas::CasCmd),

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

/// Install a custom panic hook that prints a user-friendly message.
fn setup_panic_handler() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".into());

        let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".into()
        };

        eprintln!();
        eprintln!("OAIE: internal error (this is a bug)");
        eprintln!("  at:      {location}");
        eprintln!("  message: {message}");
        eprintln!("  version: {} ({})", env!("CARGO_PKG_VERSION"), env!("OAIE_GIT_HASH"));
        eprintln!();
        eprintln!("Please report this at: https://github.com/dumitru-stama/oaie/issues");
    }));
}

fn main() {
    setup_panic_handler();

    oaie_core::log::init();

    let cli = Cli::parse();
    output::set_quiet(cli.quiet);

    // Print banner for interactive commands (not completions, not doctor/policy — they have their own layout).
    // Also suppress banner for JSON output mode — only structured JSON goes to stdout.
    let suppress_banner = matches!(&cli.command, Commands::Run(cmd) if cmd.output == commands::run::OutputFormat::Json);
    if !suppress_banner
        && !matches!(&cli.command, Commands::Completions { .. } | Commands::Doctor(_) | Commands::Cat(_) | Commands::Policy(_) | Commands::Key(_) | Commands::Session(_))
    {
        output::banner();
    }

    // Track tool exit code for `oaie run` (process exits with the tool's code).
    let mut tool_exit_code: Option<i32> = None;

    let result: oaie_core::error::Result<()> = match cli.command {
        Commands::Run(cmd) => cmd.execute().map(|code| { tool_exit_code = Some(code); }),
        Commands::Cat(cmd) => cmd.execute(),
        Commands::Check(cmd) => cmd.execute(),
        Commands::Inspect(cmd) => cmd.execute(),
        Commands::List(cmd) => cmd.execute(),
        Commands::Report(cmd) => cmd.execute(),
        Commands::Verify(cmd) => cmd.execute(),
        Commands::Replay(cmd) => cmd.execute(),
        Commands::Diff(cmd) => cmd.execute(),
        Commands::Export(cmd) => cmd.execute(),
        Commands::Clean(cmd) => cmd.execute(),
        Commands::Init(cmd) => cmd.execute(),
        Commands::Doctor(cmd) => cmd.execute(),
        Commands::Policy(cmd) => cmd.execute(),
        Commands::Firecracker(cmd) => cmd.execute(),
        Commands::Key(cmd) => cmd.execute(),
        Commands::Session(cmd) => cmd.execute(),
        Commands::Cas(cmd) => cmd.execute(),
        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "oaie", &mut std::io::stdout());
            Ok(())
        }
    };

    if let Err(e) = result {
        output::error(&format!("{e}"));
        std::process::exit(1);
    }

    // Propagate the tool's exit code so `oaie run -- false` exits 1.
    if let Some(code) = tool_exit_code {
        if code != 0 {
            std::process::exit(code);
        }
    }
}
