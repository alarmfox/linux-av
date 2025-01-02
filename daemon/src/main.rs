use std::io::Read;
use std::os::unix::net::UnixStream;

use app::{Cli, ClientCommands, Command, DaemonCommands};
use clap::Parser;
use common::CommandResult;
use serde::Deserialize;
use tracing::error;
use tracing::Level;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
                daemon::Daemon::new(cli.config_path)?.start().unwrap();
            }
        },
        Command::Client(action) => {
            let request = match action.command {
                ClientCommands::Scan { path } => common::Request {
                    command: common::Command::Scan {
                        path,
                        offline: true,
                    },
                },
                ClientCommands::Update => common::Request {
                    command: common::Command::Update,
                },
                ClientCommands::Run { path, args } => common::Request {
                    command: common::Command::Run { path, args },
                },
            };
            let mut conn = UnixStream::connect(action.socket_path)?;
            serde_json::to_writer(&conn, &request)?;
            let mut response = serde_json::Deserializer::from_reader(&conn);
            match CommandResult::deserialize(&mut response) {
                Ok(result) => {
                    let a = serde_json::to_string(&result).unwrap();
                    println!("{}", a);
                    match result {
                        CommandResult::Run(_) => {
                            let mut buf = [0; 1024];
                            loop {
                                match conn.read(&mut buf) {
                                    Ok(n) => match n {
                                        0 => break,
                                        _ => {
                                            let s = String::from_utf8(buf[..n].to_vec()).unwrap();
                                            println!("{}", s);
                                        }
                                    },
                                    Err(e) => {
                                        error!("{}", e);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    error!("cannot deserialize response {}", e.to_string());
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

    const YR_CORE_FILE: &str = "packages/core/yara-rules-core.yar";

    use std::{
        fs::{self, File},
        io::{self, BufRead, BufReader, Cursor, Read, Write},
        os::unix::{fs::PermissionsExt, net::UnixListener},
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
            Command, CommandResult, Error, ErrorResult, Request, RunResult, ScanResult,
            StatusResult, UpdateResult,
        },
        sandbox::Sandbox,
    };

    #[derive(Debug)]
    pub struct Daemon {
        version: String,

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
                config_path,
                socket_path,
            })
        }

        pub fn start(self: Self) -> Result<(), Box<dyn std::error::Error>> {
            let listener = UnixListener::bind(self.socket_path.clone())?;
            let me = Arc::new(self);

            fs::set_permissions(
                me.clone().socket_path.clone(),
                fs::Permissions::from_mode(0o777),
            )?;

            loop {
                match listener.accept() {
                    Ok((mut conn, _sa)) => {
                        let mut request = serde_json::Deserializer::from_reader(&conn);
                        let response = match Request::deserialize(&mut request) {
                            Ok(request) => match me.clone().handle_request(&request) {
                                Ok(result) => result,
                                Err(e) => CommandResult::Error(ErrorResult {
                                    kind: format!("command {} returned an error", request.command),
                                    message: Some(e.to_string()),
                                }),
                            },
                            Err(e) => CommandResult::Error(ErrorResult {
                                kind: "invalid request".to_string(),
                                message: Some(e.to_string()),
                            }),
                        };
                        match response {
                            CommandResult::Run(result) => {
                                let response = CommandResult::Run(RunResult {
                                    status: result.status,
                                    stderr: None,
                                    stdout: None,
                                });
                                let serialized_response = serde_json::to_vec(&response).unwrap();
                                conn.write(&serialized_response).unwrap();
                                if let Some(stdout) = result.stdout {
                                    while let Ok(data) = stdout.recv() {
                                        conn.write_all(&data).unwrap();
                                    }
                                }
                            }
                            _ => {
                                serde_json::to_writer(conn, &response).unwrap();
                            }
                        }
                    }
                    Err(e) => error!("accept function failed: {:?}", e),
                }
            }
        }

        #[tracing::instrument(skip(self), level = "trace", ret)]
        fn handle_request(self: Arc<Self>, request: &Request) -> Result<CommandResult, Error> {
            let me = self.clone();
            match &request.command {
                Command::Scan { path, .. } => {
                    if path.is_dir() {
                        todo!();
                    }

                    let path1 = path.clone();
                    let mut file = File::open(path1).unwrap();
                    let mut sha256 = Sha256::new();
                    io::copy(&mut file, &mut sha256).map_err(Error::IoError)?;
                    let hash = sha256.finalize();
                    let hash = format!("{:x}", hash);

                    let is_threat = me.scan_sig(hash.as_str())?;

                    let path = path.clone();
                    let yara_result = self.yara_scan(path).map_err(Error::YaraError)?;

                    Ok(CommandResult::Scan(ScanResult {
                        threat: is_threat,
                        intelligence: Some(yara_result),
                    }))
                }
                Command::Update => {
                    download_and_extract(MB_SHA256_URL, me.config_path.clone()).unwrap();
                    download_and_extract(YR_CORE_URL, me.config_path.clone()).unwrap();

                    //TODO: handle results

                    Ok(CommandResult::Update(UpdateResult { status: 0 }))
                }
                Command::Status => Ok(CommandResult::Status(StatusResult {
                    version: self.version.clone(),
                })),
                Command::Run { path, args } => {
                    let sandbox = Sandbox::new(&self.config_path).map_err(Error::SandboxError)?;
                    let run_result = match sandbox.run(path, args.clone()) {
                        Ok((stdout, stderr)) => RunResult {
                            status: 0,
                            stdout: Some(stdout),
                            stderr: Some(stderr),
                        },
                        Err(e) => {
                            error!("{:?}", e);
                            RunResult {
                                status: -1,
                                stdout: None,
                                stderr: None,
                            }
                        }
                    };
                    sandbox.delete().unwrap();
                    Ok(CommandResult::Run(run_result))
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
            let yr_path = self.config_path.join(YR_CORE_FILE);

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

    fn download_and_extract(url: &str, dest_directory: PathBuf) -> Result<(), Error> {
        let mut tempfile = tempfile().map_err(|e| Error::IoError(e))?;
        let response = reqwest::blocking::get(url)
            .map_err(Error::NetworkError)?
            .bytes()
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
        sync::mpsc::Receiver,
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
    }
    #[derive(Serialize, Deserialize, Debug)]
    pub struct RunResult {
        pub status: i32,
        #[serde(skip)]
        pub stdout: Option<Receiver<Vec<u8>>>,
        #[serde(skip)]
        pub stderr: Option<Receiver<Vec<u8>>>,
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
        Client(SimpleClient),
        Daemon(Daemon),
    }

    #[derive(Parser)]
    pub struct SimpleClient {
        #[structopt(subcommand)]
        pub command: ClientCommands,

        #[arg(short, long, default_value = "/tmp/linux-av/linux-av.sock")]
        pub socket_path: PathBuf,
    }

    #[derive(Subcommand)]
    pub enum ClientCommands {
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
        fs::{self, create_dir_all, remove_dir_all, File},
        io::{self, BufReader, Read, Write},
        os::{
            fd::FromRawFd,
            unix::net::{UnixListener, UnixStream},
        },
        path::PathBuf,
        sync::mpsc::{self, Receiver},
        thread::{self, JoinHandle},
    };

    use nix::{
        errno::Errno,
        fcntl::OFlag,
        libc::{STDERR_FILENO, STDOUT_FILENO},
        sched::{clone, CloneFlags},
        sys::{
            signal::{kill, Signal},
            wait::{waitpid, WaitStatus},
        },
        unistd::{chroot, close, dup2, execv, pipe2, Pid},
    };
    use serde::{Deserialize, Serialize};
    use tar::Archive;
    use tracing::error;
    use uuid::Uuid;

    pub struct Sandbox {
        id: String,
        base_path: PathBuf,
        root_path: PathBuf,
        control_path: PathBuf,

        shim_pid: Option<Pid>,
        request_pipe: Option<File>,
        response_pipe: Option<File>,

        reader_thread: Option<JoinHandle<()>>,
    }

    impl Sandbox {
        pub fn get_root_path(&self) -> PathBuf {
            return self.root_path.clone();
        }
    }

    #[derive(Serialize, Deserialize)]
    enum ShimCommand {
        Exit,
        Ping,
        Run { path: PathBuf, args: Option<String> },
    }

    #[derive(Debug)]
    pub enum Error {
        OsError(nix::Error),
        Custom(String),
    }
    impl Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Error::OsError(e) => write!(f, "OS error: {}", e),
                Error::Custom(e) => write!(f, "Unknown: {}", e),
            }
        }
    }

    impl Sandbox {
        pub fn new(base_path: &PathBuf) -> Result<Self, Error> {
            let id = format!("sandbox.{}", Uuid::new_v4());
            let base_path = base_path.join(PathBuf::from(id.clone()));
            let root_path = base_path.join(PathBuf::from("root"));
            let control_path = root_path.join(PathBuf::from("control.sock"));
            let mut sandbox = Sandbox {
                id,
                base_path: base_path.clone(),
                root_path: root_path.clone(),
                control_path: control_path.clone(),
                shim_pid: None,
                request_pipe: None,
                response_pipe: None,
                reader_thread: None,
            };

            // create base structure
            Self::create_base_structure(&root_path).unwrap();

            // create shim
            let shim_pid = sandbox.create_shim().unwrap();

            sandbox.shim_pid = Some(shim_pid);

            Ok(sandbox)
        }

        pub fn run(
            &self,
            program: &PathBuf,
            args: Option<String>,
        ) -> Result<(Receiver<Vec<u8>>, Receiver<Vec<u8>>), Error> {
            let path = PathBuf::from("/tmp").join(program.file_name().unwrap());
            let full_path = self
                .root_path
                .join("tmp")
                .join(program.file_name().unwrap());
            fs::copy(program, &full_path).expect("Failed to copy program to launch path");

            let mut conn =
                UnixStream::connect(self.control_path.clone()).expect("Client cannot send request");

            let request = ShimCommand::Run { path, args };

            serde_json::to_writer(&conn, &request).unwrap();

            let (tx_stdout, rx_stdout) = mpsc::channel::<Vec<u8>>();
            let (tx_stderr, rx_stderr) = mpsc::channel::<Vec<u8>>();
            thread::spawn(move || {
                let mut buffer = [0; 1024];
                while let Ok(n) = conn.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    // Send a new Vec<u8> with the data
                    tx_stdout.send(buffer[..n].to_vec()).unwrap();
                }
            })
            .join()
            .unwrap();

            Ok((rx_stdout, rx_stderr))
        }

        pub fn delete(&self) -> Result<(), io::Error> {
            if let Some(pid) = self.shim_pid {
                kill(pid, Signal::SIGKILL).unwrap();
            }
            remove_dir_all(self.base_path.clone())
        }

        fn create_shim(&self) -> Result<Pid, Error> {
            let stack_size = 1024 * 1024;
            let mut stack: Vec<u8> = vec![0; stack_size];

            let clone_flags = CloneFlags::CLONE_NEWUSER
                | CloneFlags::CLONE_NEWNET
                | CloneFlags::CLONE_NEWPID
                | CloneFlags::CLONE_NEWUTS
                | CloneFlags::CLONE_NEWNS;

            let child = clone(
                Box::new(|| {
                    let listener = UnixListener::bind(self.control_path.clone()).unwrap();
                    if let Err(e) = chroot(&self.root_path) {
                        error!("Error changing root: {:?}", e);
                        return -1;
                    }
                    std::env::set_current_dir("/").unwrap();

                    loop {
                        match listener.accept() {
                            Ok((mut conn, _)) => {
                                let mut request = serde_json::Deserializer::from_reader(&conn);
                                match ShimCommand::deserialize(&mut request) {
                                    Ok(cmd) => match cmd {
                                        ShimCommand::Run { path, args } => {
                                            let stdout = pipe2(OFlag::O_CLOEXEC).unwrap();
                                            let stderr = pipe2(OFlag::O_CLOEXEC).unwrap();
                                            match self.run_process(&path, args, stdout, stderr) {
                                                Ok(_) => {
                                                    let mut stdout_reader =
                                                        BufReader::new(unsafe {
                                                            File::from_raw_fd(stdout.0)
                                                        });

                                                    let mut stdout_buffer = [0; 1024];

                                                    loop {
                                                        match stdout_reader
                                                            .read(&mut stdout_buffer)
                                                            .unwrap()
                                                        {
                                                            0 => break,
                                                            n => conn
                                                                .write_all(&stdout_buffer[..n])
                                                                .unwrap(),
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    println!("process not exited correctly {:?}", e)
                                                }
                                            };
                                        }
                                        ShimCommand::Exit => {
                                            println!("Shim: exit command recvd");
                                            break;
                                        }
                                        ShimCommand::Ping => {
                                            println!("Shim: ping command recvd");
                                        }
                                    },
                                    Err(e) => {
                                        error!("cannot deserialize command {}", e)
                                    }
                                }
                            }
                            Err(e) => {
                                error!("cannot accept connection {}", e);
                                break;
                            }
                        };
                    }
                    0
                }),
                &mut stack,
                clone_flags,
                Some(nix::libc::SIGCHLD),
            )
            .unwrap();

            loop {
                match UnixStream::connect(self.control_path.clone()) {
                    Ok(socket) => {
                        serde_json::to_writer(socket, &ShimCommand::Ping).unwrap();
                        break;
                    }
                    Err(_) => {}
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }

            Ok(child)
        }

        fn run_process(
            &self,
            program: &PathBuf,
            args: Option<String>,
            (stdout_read, stdout_write): (i32, i32),
            (stderr_read, stderr_write): (i32, i32),
        ) -> Result<(), Errno> {
            let stack_size = 1024 * 1024;
            let mut stack: Vec<u8> = vec![0; stack_size];

            let clone_flags = CloneFlags::CLONE_IO | CloneFlags::CLONE_FS;
            let child = clone(
                Box::new(|| {
                    // Redirect stdout
                    dup2(stdout_write, STDOUT_FILENO).unwrap();
                    close(stdout_write).unwrap(); // Close write end after dup2

                    // Redirect stderr
                    dup2(stderr_write, STDERR_FILENO).unwrap();
                    close(stderr_write).unwrap(); // Close write end after dup2

                    close(stdout_read).unwrap(); // Close read end in child
                    close(stderr_read).unwrap();

                    let executable = CString::new(program.to_str().unwrap())
                        .expect("Error converting program path");

                    let args_vec: Vec<CString> = match &args {
                        Some(arg_string) => {
                            vec![executable, CString::new(arg_string.to_string()).unwrap()]
                        }
                        None => vec![executable],
                    };
                    match execv(&args_vec[0], &args_vec) {
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

            match child {
                Ok(pid) => match waitpid(pid, None).unwrap() {
                    WaitStatus::Exited(_, status) => match status {
                        0 => {
                            close(stdout_write).unwrap(); // Close write ends in parent
                            close(stderr_write).unwrap(); // Close write ends in parent
                            Ok(())
                        }
                        s => {
                            println!("process exited with non-zero status {:?}", s);
                            Err(Errno::from_i32(s))
                        }
                    },
                    WaitStatus::Signaled(_, _, _) => Ok(()),
                    _ => {
                        println!("Process terminated in an unexpected way");
                        Ok(())
                    }
                },
                Err(e) => Err(e),
            }
        }

        fn create_base_structure(root_path: &PathBuf) -> Result<(), Error> {
            create_dir_all(&root_path)
                .expect("Cannot initiate sandbox. Failed to create directory");

            let file = File::open("/tmp/linux-av/busybox.tar")
                .expect("Busybox not found. Check your installation");
            Archive::new(file)
                .unpack(&root_path)
                .expect("Cannot unpack base system into sandbox filesystem");

            create_dir_all(root_path.join("tmp")).expect("Failed to create tmp directory");
            Ok(())
        }
    }

    #[cfg(test)]
    mod test {
        use std::{
            fs::{File, Permissions},
            io::Write,
            os::unix::fs::PermissionsExt,
            path::PathBuf,
        };

        use crate::sandbox::Sandbox;

        #[test]
        fn execute_simple_shell_command() {
            let script = r" 
                #! /bin/sh
                echo hello $1";

            let sandbox = Sandbox::new(&PathBuf::from("/tmp")).expect("cannot create sandbox");
            let script_path = sandbox.base_path.join("script.sh");
            let mut f = File::create(script_path.clone()).unwrap();
            f.write_all(script.trim().as_bytes()).unwrap();
            f.set_permissions(Permissions::from_mode(0o777)).unwrap();

            let result = sandbox.run(&script_path, Some("world".to_string()));

            let result = result.unwrap().0;
            let string = String::from_utf8(result.recv().unwrap()).unwrap();

            assert_eq!(string, "hello world\n");

            sandbox.delete().expect("Cannot delete sandbox");
        }
    }
}
