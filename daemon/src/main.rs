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
                SimpleClientCommands::Run { path, args } => common::Request {
                    command: common::Command::Run { path, args },
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
    const PIDFILE_PATH: &str = "daemon.pid";

    const YR_CORE_URL: &str =
        "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";

    const YR_CORE_FILE: [&'static str; 3] = ["packages", "core", "yara-rules-core.yar"];

    use std::{
        ffi::CString,
        fs::{self, File},
        io::{self, BufRead, BufReader, Cursor},
        os::unix::{
            fs::{chroot, PermissionsExt},
            net::{SocketAddr, UnixListener, UnixStream},
        },
        path::PathBuf,
        process,
        sync::Arc,
    };

    use serde::Deserialize;
    use sha2::{Digest, Sha256};
    use tempfile::tempfile;
    use tracing::{debug, error};
    use yara::Compiler;
    use zip::ZipArchive;

    use crate::{
        common::{
            Command, CommandResult, Error, ErrorResult, Request, RequestType, RunResult,
            ScanResult, StatusResult, UpdateResult,
        },
        sandbox::Sandbox,
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

            let pid = process::id();
            fs::write(config_path.join(PIDFILE_PATH), pid.to_string())?;

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

            fs::set_permissions(
                me.clone().socket_path.clone(),
                fs::Permissions::from_mode(0o777),
            )?;

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
                Command::Run { path, args } => {
                    let sandbox = Sandbox::new(&self.config_path).map_err(Error::SandboxError)?;
                    let run_result = match sandbox.run(path, args.clone()).await {
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

    use crate::sandbox;

    #[derive(Serialize, Deserialize, Debug)]
    #[serde(rename_all = "snake_case")]
    pub enum Command {
        Scan { path: PathBuf, offline: bool },
        Status,
        Update,
        Run { path: PathBuf, args: Option<String> },
    }

    impl Display for Command {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Command::Scan { offline, path } => {
                    write!(f, "scan(path={:?}, offline={})", path, offline)
                }
                Command::Status => write!(f, "status"),
                Command::Update => write!(f, "update"),
                Command::Run { path, args } => {
                    write!(f, "run(path={:?}, args={:?})", path, args)
                }
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
        SandboxError(sandbox::Error),
    }

    impl Display for Error {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Error::NetworkError(e) => write!(f, "Network error: {}", e),
                Error::IoError(e) => write!(f, "IO error: {}", e),
                Error::ZipError => write!(f, "Zip error"),
                Error::YaraError(e) => write!(f, "Yara error: {}", e),
                Error::SandboxError(e) => write!(f, "Sandbox error: {}", e),
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
            #[arg(long)]
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

mod sandbox {

    use std::{
        ffi::CString,
        fmt::Display,
        fs::{create_dir_all, remove_dir_all, File},
        io::{self, BufRead, BufWriter, Read},
        os::fd::FromRawFd,
        path::PathBuf,
    };

    use nix::{
        fcntl::OFlag,
        libc::{O_DIRECT, STDOUT_FILENO},
        mount::{mount, MsFlags},
        sched::{clone, CloneFlags},
        sys::wait::{waitpid, WaitStatus},
        unistd::{chroot, close, dup2, execv, execvp, pipe2},
    };
    use tar::Archive;
    use tracing::error;
    use uuid::Uuid;

    pub struct Sandbox {
        id: String,
        path: PathBuf,
    }

    #[derive(Debug)]
    pub enum Error {
        OsError(nix::Error),
    }
    impl Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Error::OsError(e) => write!(f, "OS error: {}", e),
            }
        }
    }

    impl Sandbox {
        pub fn new(base_path: &PathBuf) -> Result<Self, Error> {
            let id = format!("sandbox.{}", Uuid::new_v4());
            let path = base_path.join(PathBuf::from(id.clone()));

            create_dir_all(&path).expect("Cannot initiate sandbox. Failed to create directory");

            let file = File::open("/tmp/linux-av/distrobox.tar")
                .expect("Distrobox not found. Check your installation");
            Archive::new(file)
                .unpack(&path)
                .expect("Cannot unpack base system into sandbox filesystem");

            create_dir_all(path.join("monitor")).expect("Failed to create monitor directory");

            Ok(Sandbox { id, path })
        }
        pub async fn run(&self, path: &PathBuf, args: Option<String>) -> Result<(), Error> {
            let stack_size = 1024 * 1024;
            let mut stack: Vec<u8> = vec![0; stack_size];

            let clone_flags =
                CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNET | CloneFlags::CLONE_NEWNS;

            let pipe_stdout = pipe2(OFlag::O_DIRECT | OFlag::O_CLOEXEC).unwrap();
            let pipe_stderr = pipe2(OFlag::O_DIRECT | OFlag::O_CLOEXEC).unwrap();

            let stdout_path = self.path.join("monitor").join("stdout");
            let stderr_path = self.path.join("monitor").join("stderr");
            let monitor_handle = tokio::spawn(async move {
                close(pipe_stdout.1).unwrap();
                close(pipe_stderr.1).unwrap();
                write_raw_fd(&stdout_path, pipe_stdout.0).unwrap();
                write_raw_fd(&stderr_path, pipe_stderr.0).unwrap();
            });
            let child = clone(
                Box::new(|| {
                    if let Err(e) = chroot(&self.path) {
                        error!("Error changing root: {:?}", e);
                        return -1;
                    }
                    std::env::set_current_dir("/").unwrap();

                    // Prepare the program and arguments to execute
                    let c_program = CString::new(path.to_str().unwrap())
                        .expect("Error converting program path");

                    // Execute the specified program
                    let mut args = match &args {
                        Some(args) => args
                            .split_whitespace()
                            .map(|s| CString::new(s).unwrap())
                            .collect(),
                        None => vec![],
                    };
                    args.insert(0, c_program);
                    close(STDOUT_FILENO).unwrap();
                    close(pipe_stdout.0).unwrap();
                    dup2(pipe_stdout.1, STDOUT_FILENO).unwrap();
                    match execv(&args[0], &args) {
                        Ok(_) => 0,
                        Err(err) => {
                            error!("Error executing program: {:?}", err);
                            -1
                        }
                    }
                }),
                &mut stack,
                clone_flags,
                Some(nix::libc::SIGCHLD),
            );

            let process_output = match child {
                Ok(pid) => match waitpid(pid, None).unwrap() {
                    WaitStatus::Exited(_, _) => Ok(()),
                    WaitStatus::Signaled(_, _, _) => Ok(()),
                    _ => {
                        error!("Process terminated in an unexpected way");
                        Ok(())
                    }
                },
                Err(e) => Err(Error::OsError(e)),
            };

            tokio::join!(monitor_handle).0.unwrap();
            return process_output;
        }
        pub fn delete(&self) -> Result<(), io::Error> {
            remove_dir_all(self.path.clone())
        }
    }

    impl Sandbox {
        pub fn get_path(&self) -> PathBuf {
            return self.path.clone();
        }
    }

    fn write_raw_fd(dest: &PathBuf, fd: i32) -> Result<u64, io::Error> {
        let f = unsafe { File::from_raw_fd(fd) };
        let mut reader = io::BufReader::new(f);
        let dest = File::create(dest).unwrap();
        let mut writer = io::BufWriter::new(dest);
        io::copy(&mut reader, &mut writer)
    }

    #[cfg(test)]
    mod test {
        use std::path::PathBuf;

        use crate::sandbox::Sandbox;

        #[tokio::test]
        async fn execute_simple_shell_command() {
            let sandbox = Sandbox::new(&PathBuf::from("/tmp"));
            assert!(sandbox.is_ok());
            assert!(sandbox
                .unwrap()
                .run(&PathBuf::from("/bin/ls"), Some("-la".to_string()))
                .await
                .is_ok());
            // assert_file_content(&sandbox.get_path().join(stdout_path), expected);
        }
    }
}
