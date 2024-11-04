use std::{fs, os::unix::net::UnixStream};

use app::{Cli, Command, DaemonCommands, SimpleClientCommands};
use clap::Parser;
use common::CommandResult;
use serde::Deserialize;
use tracing::error;
use tracing::Level;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    // You can see how many times a particular flag or argument occurred
    // Note, only flags can have multiple occurrences
    let log_level = match cli.verbose {
        0 => Level::ERROR,
        1 => Level::INFO,
        2 => Level::DEBUG,
        _ => Level::TRACE,
    };
    // setup logging
    // Set up the default subscriber
    tracing_subscriber::fmt()
        // all spans/events with a level higher than TRACE (e.g, info, warn, etc.)
        // will be written to stdout.
        .with_max_level(log_level)
        // sets this to be the default, global collector for this application.
        .init();

    match cli.command {
        Command::Daemon(action) => match action.command {
            DaemonCommands::Start => {
                daemon::Daemon::new(cli.config_path)?.start().await?;
            }
        },
        Command::SimpleClient(action) => {
            let request = match action.command {
                SimpleClientCommands::Scan { path } => common::Request {
                    command: common::Command::Scan {
                        path,
                        offline: true,
                    },
                },
                SimpleClientCommands::Update => common::Request {
                    command: common::Command::Update,
                },
                SimpleClientCommands::Run {
                    path,
                    timeout_seconds,
                    args,
                } => common::Request {
                    command: common::Command::Run {
                        path,
                        timeout_seconds,
                        args,
                    },
                },
            };
            let request = common::RequestType::Simple(request);
            let conn = UnixStream::connect(action.socket_path)?;
            serde_json::to_writer(&conn, &request)?;
            let mut response = serde_json::Deserializer::from_reader(&conn);
            match CommandResult::deserialize(&mut response) {
                Ok(result) => {
                    let a = serde_json::to_string(&result).unwrap();
                    println!("{}", a);
                }
                Err(e) => {
                    error!("{}", e.to_string());
                }
            }
        }
    };

    Ok(())
}

mod daemon {
    const MB_SHA256_URL: &str = "https://bazaar.abuse.ch/export/txt/sha256/full/";
    const MB_SHA256_FILE: &str = "full_sha256.txt";
    const VERSION: &str = "v0.1-alpha";

    const SOCKET_PATH: &str = "linux-av.sock";

    const YR_CORE_URL: &str =
        "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";

    const YR_CORE_FILE: [&'static str; 3] = ["packages", "core", "yara-rules-core.yar"];

    use std::{
        ffi::CString,
        fs::{self, File},
        io::{self, BufRead, BufReader, Cursor},
        os::unix::net::{SocketAddr, UnixListener, UnixStream},
        path::PathBuf,
        sync::Arc,
    };

    use nix::{
        mount::{mount, MsFlags},
        sched::{clone, CloneFlags},
        sys::{
            signal::Signal::SIGCHLD,
            wait::{waitpid, WaitStatus},
        },
        unistd::{execvp, setuid, Uid},
    };
    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use tempfile::tempfile;
    use tracing::{debug, error};
    use yara::Compiler;
    use zip::ZipArchive;

    use crate::common::{
        Command, CommandResult, Error, ErrorResult, Request, RequestType, RunResult, ScanResult,
        StatusResult, UpdateResult,
    };

    #[derive(Debug)]
    pub struct Daemon {
        version: String,
        rtp_on: bool,

        socket_path: PathBuf,
        config_path: PathBuf,
    }
    impl Daemon {
        pub fn new(config_path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
            fs::create_dir_all(config_path.clone())?;
            let socket_path = config_path.join(SOCKET_PATH);
            match fs::remove_file(socket_path.clone()) {
                Ok(()) => {
                    debug!("deleted old file {:?}", socket_path.clone());
                    Ok(())
                }
                Err(e) => match e.kind() {
                    std::io::ErrorKind::NotFound => Ok(()),
                    _ => Err(e),
                },
            }?;
            Ok(Self {
                version: VERSION.to_string(),
                rtp_on: false,
                config_path,
                socket_path,
            })
        }

        pub async fn start(self: Self) -> Result<(), Box<dyn std::error::Error>> {
            let listener = UnixListener::bind(self.socket_path.clone())?;
            let me = Arc::new(self);

            loop {
                match listener.accept() {
                    Ok((socket, sa)) => {
                        let mut request = serde_json::Deserializer::from_reader(&socket);
                        let response = match RequestType::deserialize(&mut request) {
                            Ok(request_type) => match request_type {
                                RequestType::Simple(request) => {
                                    match me.clone().handle_simple_request(&request).await {
                                        Ok(result) => result,
                                        Err(e) => CommandResult::Error(ErrorResult {
                                            kind: format!(
                                                "command {} returned an error",
                                                request.command
                                            ),
                                            message: Some(e.to_string()),
                                        }),
                                    }
                                }
                                RequestType::Persistent => {
                                    match me.clone().handle_persistent_connection(socket, sa).await
                                    {
                                        Ok(_) => {}
                                        Err(e) => error!("{:?}", e),
                                    };
                                    continue;
                                }
                            },
                            Err(e) => CommandResult::Error(ErrorResult {
                                kind: "invalid request".to_string(),
                                message: Some(e.to_string()),
                            }),
                        };
                        serde_json::to_writer(socket, &response).unwrap();
                    }
                    Err(e) => error!("accept function failed: {:?}", e),
                }
            }
        }

        #[tracing::instrument(skip(self), level = "trace", ret)]
        async fn handle_simple_request(
            self: Arc<Self>,
            request: &Request,
        ) -> Result<CommandResult, Error> {
            let me = self.clone();
            match &request.command {
                Command::Scan { path, .. } => {
                    if path.is_dir() {
                        todo!();
                    }

                    let path1 = path.clone();
                    let t1 = tokio::spawn(async {
                        let mut file = File::open(path1).unwrap();
                        let mut sha256 = Sha256::new();
                        io::copy(&mut file, &mut sha256).map_err(Error::IoError)?;
                        let hash = sha256.finalize();
                        let hash = format!("{:x}", hash);

                        me.scan_sig(hash.as_str())
                    });

                    let path = path.clone();
                    let t2 = tokio::spawn(async move { self.yara_scan(path) });

                    let (r1, r2) = tokio::join!(t1, t2);
                    let is_threat = r1.unwrap()?;

                    let yr_result = r2.unwrap().map_err(Error::YaraError)?;

                    Ok(CommandResult::Scan(ScanResult {
                        threat: is_threat,
                        intelligence: Some(yr_result),
                    }))
                }
                Command::Update => {
                    let t1 =
                        tokio::spawn(download_and_extract(MB_SHA256_URL, me.config_path.clone()));
                    let t2 =
                        tokio::spawn(download_and_extract(YR_CORE_URL, me.config_path.clone()));

                    let (r1, r2) = tokio::join!(t1, t2);
                    //TODO: handle results

                    Ok(CommandResult::Update(UpdateResult { status: 0 }))
                }
                Command::Status => Ok(CommandResult::Status(StatusResult {
                    rtp_on: self.rtp_on.clone(),
                    version: self.version.clone(),
                })),
                Command::Run {
                    path,
                    timeout_seconds,
                    args,
                } => {
                    let run_result = match me.clone().run_in_sandbox(path, args.clone()) {
                        Ok(()) => RunResult { status: 0 },
                        Err(e) => {
                            error!("{:?}", e);
                            RunResult { status: 1 }
                        }
                    };
                    Ok(CommandResult::Run(run_result))
                }
            }
        }

        #[tracing::instrument(skip(self), level = "trace")]
        async fn handle_persistent_connection(
            self: Arc<Self>,
            socket: UnixStream,
            peer: SocketAddr,
        ) -> Result<(), Error> {
            let me = self.clone();
            loop {
                let mut request = serde_json::Deserializer::from_reader(&socket);
                let response = match Request::deserialize(&mut request) {
                    Ok(request) => match me.clone().handle_simple_request(&request).await {
                        Ok(result) => result,
                        Err(e) => CommandResult::Error(ErrorResult {
                            kind: format!("command {} returned an error", request.command),
                            message: Some(e.to_string()),
                        }),
                    },
                    Err(e) => CommandResult::Error(ErrorResult {
                        kind: format!("bad request"),
                        message: Some(e.to_string()),
                    }),
                };
                serde_json::to_writer(&socket, &response).unwrap();
            }
        }

        fn run_in_sandbox(
            self: Arc<Self>,
            path: &PathBuf,
            args: Option<String>,
        ) -> Result<(), Error> {
            let stack_size = 1024 * 1024;
            let mut stack: Vec<u8> = vec![0; stack_size];

            // Temporarily gain root privileges
            let root_uid = Uid::from_raw(0);
            setuid(root_uid).expect("Failed to gain root privileges");

            let clone_flags =
                CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS;

            let child_pid = clone(
                Box::new(|| {
                    // Set up a new mount namespace
                    // if let Err(e) = mount(
                    //     Some("none"),
                    //     "/",
                    //     Some(""),
                    //     MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                    //     None::<&str>,
                    // ) {
                    //     error!("Error setting up mount namespace: {:?}", e);
                    //     return -1;
                    // }
                    //
                    // Mount a temporary filesystem
                    if let Err(e) = mount(
                        Some("tmpfs"),
                        "/tmp",
                        Some("tmpfs"),
                        MsFlags::empty(),
                        None::<&str>,
                    ) {
                        error!("Error mounting tmpfs: {:?}", e);
                        return -1;
                    }

                    // Prepare the program and arguments to execute
                    let c_program = CString::new(path.to_str().unwrap())
                        .expect("Error converting program path");

                    // Execute the specified program
                    let args: Vec<CString> = vec![];
                    match execvp(&c_program, &args) {
                        Ok(_) => 0,
                        Err(err) => {
                            error!("Error executing program: {:?}", err);
                            -1
                        }
                    }
                }),
                &mut stack,
                clone_flags,
                Some(17),
            )
            .unwrap();

            let non_root_uid = Uid::from_raw(1000);
            setuid(non_root_uid).expect("Failed to drop root privileges");

            // Aspetta che il processo figlio termini
            match waitpid(child_pid, None).unwrap() {
                WaitStatus::Exited(_, status) => {
                    println!("Il processo figlio è terminato con stato: {}", status);
                    Ok(())
                }
                WaitStatus::Signaled(_, signal, _) => {
                    println!("Il processo figlio è terminato per segnale: {}", signal);
                    Ok(())
                }
                _ => {
                    eprintln!("Il processo figlio è terminato in modo inatteso");
                    Ok(())
                }
            }
        }

        fn scan_sig(self: Arc<Self>, hash: &str) -> Result<bool, Error> {
            let file = File::open(self.config_path.clone().join(MB_SHA256_FILE))
                .map_err(Error::IoError)?;

            let reader = BufReader::new(file);

            for line in reader.lines() {
                if let Ok(a) = line {
                    if a == hash {
                        return Ok(true);
                    }
                }
            }
            Ok(false)
        }

        fn yara_scan(self: Arc<Self>, target: PathBuf) -> Result<Vec<String>, yara::errors::Error> {
            let yr_path = self
                .config_path
                .join(YR_CORE_FILE[0])
                .join(YR_CORE_FILE[1])
                .join(YR_CORE_FILE[2]);

            let compiler = Compiler::new()?.add_rules_file(yr_path)?;

            let rules = compiler.compile_rules()?;
            let result = rules
                .scan_file(target, 60)?
                .iter()
                .map(|r| r.identifier.to_string())
                .collect::<Vec<String>>();

            Ok(result)
        }
    }

    async fn download_and_extract(url: &str, dest_directory: PathBuf) -> Result<(), Error> {
        let mut tempfile = tempfile().map_err(|e| Error::IoError(e))?;
        let response = reqwest::get(url)
            .await
            .map_err(Error::NetworkError)?
            .bytes()
            .await
            .map_err(Error::NetworkError)?;

        let mut stream = Cursor::new(response);

        let _ = io::copy(&mut stream, &mut tempfile).map_err(Error::IoError)?;

        ZipArchive::new(tempfile)
            .map_err(|_| Error::ZipError)?
            .extract(dest_directory)
            .map_err(|_| Error::ZipError)?;

        Ok(())
    }
}

mod common {
    use std::{
        fmt::{self, Display},
        io,
        path::PathBuf,
    };

    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "snake_case")]
    pub enum Command {
        Scan {
            path: PathBuf,
            offline: bool,
        },
        Status,
        Update,
        Run {
            path: PathBuf,
            timeout_seconds: Option<u64>,
            args: Option<String>,
        },
    }

    impl Display for Command {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Command::Scan { offline, path } => {
                    write!(f, "scan(path={:?}, offline={})", path, offline)
                }
                Command::Status => write!(f, "status"),
                Command::Update => write!(f, "update"),
                Command::Run {
                    path,
                    timeout_seconds,
                    args,
                } => write!(
                    f,
                    "run(path={:?}, timeout={:?}, args={:?})",
                    path, timeout_seconds, args
                ),
            }
        }
    }
    #[derive(Deserialize, Serialize, Debug)]
    #[serde(rename_all = "snake_case")]
    pub enum RequestType {
        Simple(Request),
        Persistent,
    }

    #[derive(Deserialize, Serialize, Debug)]
    pub struct Request {
        pub command: Command,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct UpdateResult {
        pub status: i32,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct ScanResult {
        pub threat: bool,
        pub intelligence: Option<Vec<String>>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    pub struct StatusResult {
        pub version: String,
        pub rtp_on: bool,
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct RunResult {
        pub status: i32,
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct ErrorResult {
        pub kind: String,
        pub message: Option<String>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "snake_case")]
    pub enum CommandResult {
        Scan(ScanResult),
        Update(UpdateResult),
        Status(StatusResult),
        Run(RunResult),
        Error(ErrorResult),
    }

    #[derive(Debug)]
    pub enum Error {
        NetworkError(reqwest::Error),
        IoError(io::Error),
        ZipError,
        YaraError(yara::errors::Error),
    }

    impl Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Error::NetworkError(e) => write!(f, "Network error: {}", e),
                Error::IoError(e) => write!(f, "IO error: {}", e),
                Error::ZipError => write!(f, "Zip error"),
                Error::YaraError(e) => write!(f, "Yara error: {}", e),
            }
        }
    }
}
mod app {
    use clap::{Parser, Subcommand};
    use std::path::PathBuf;

    #[derive(Parser)]
    #[command(version, about, long_about = None)]
    pub struct Cli {
        /// Turn debugging information on
        #[arg(short, action = clap::ArgAction::Count)]
        pub verbose: u8,

        #[arg(short, long, default_value = "/tmp/linux-av")]
        pub config_path: PathBuf,

        #[command(subcommand)]
        pub command: Command,
    }

    #[derive(Subcommand)]
    pub enum Command {
        SimpleClient(SimpleClient),
        Daemon(Daemon),
    }

    #[derive(Parser)]
    pub struct SimpleClient {
        #[structopt(subcommand)]
        pub command: SimpleClientCommands,

        #[arg(short, long, default_value = "/tmp/linux-av/linux-av.sock")]
        pub socket_path: PathBuf,
    }

    #[derive(Subcommand)]
    pub enum SimpleClientCommands {
        Scan {
            path: PathBuf,
        },
        Update,
        Run {
            path: PathBuf,
            timeout_seconds: Option<u64>,
            args: Option<String>,
        },
    }
    #[derive(Parser)]
    pub struct Daemon {
        #[structopt(subcommand)]
        pub command: DaemonCommands,
    }

    #[derive(Subcommand)]
    pub enum DaemonCommands {
        Start,
    }
}
