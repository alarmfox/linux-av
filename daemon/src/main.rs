use std::{
    fs::{self},
    path::PathBuf,
};

use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Turn debugging information on
    #[arg(short, action = clap::ArgAction::Count)]
    verbose: u8,

    #[arg(short, long, default_value = "/tmp/linux-av.sock")]
    unix_socket: PathBuf,

    #[arg(short, long, default_value = "/tmp/linux-av")]
    config_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // You can see how many times a particular flag or argument occurred
    // Note, only flags can have multiple occurrences
    match cli.verbose {
        0 => println!("Debug mode is off"),
        1 => println!("Debug mode is kind of on"),
        2 => println!("Debug mode is on"),
        3 => println!("Tracing mode is on"),
        _ => println!("Don't be crazy"),
    }

    fs::create_dir_all(&cli.config_dir)?;
    daemon::Daemon::new(cli.unix_socket, cli.config_dir)
        .start()
        .await?;

    Ok(())
}

mod daemon {
    const MB_SHA256_URL: &str = "https://bazaar.abuse.ch/export/txt/sha256/full/";
    const MB_SHA256_FILE: &str = "full_sha256.txt";
    const VERSION: &str = "v0.1-alpha";

    const YR_CORE_URL: &str =
        "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";

    const YR_CORE_FILE: [&'static str; 3] = ["packages", "core", "yara-rules-core.yar"];

    use std::{
        fmt::{self, Display},
        fs::File,
        io::{self, BufRead, BufReader, Cursor},
        os::unix::net::UnixListener,
        path::PathBuf,
        sync::Arc,
    };

    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use tempfile::tempfile;
    use yara::{Compiler, YaraError};
    use zip::ZipArchive;

    #[derive(Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Command {
        Scan { path: PathBuf, offline: bool },
        Status,
        Update,
    }

    impl Display for Command {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Command::Scan { offline, .. } => {
                    write!(f, "scan(path=***, offline={})", offline)
                }
                Command::Status => write!(f, "status"),
                Command::Update => write!(f, "update"),
            }
        }
    }

    #[derive(Deserialize)]
    pub struct Request {
        command: Command,
    }

    #[derive(Serialize)]
    pub struct UpdateResult {
        status: i32,
    }

    #[derive(Serialize)]
    pub struct ScanResult {
        threat: bool,
        intelligence: Option<Vec<String>>,
    }

    #[derive(Serialize)]
    pub struct StatusResult {
        version: String,
        rtp_on: bool,
    }
    #[derive(Serialize)]
    pub struct ErrorResult {
        kind: String,
        message: Option<String>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "snake_case")]
    pub enum CommandResult {
        Scan(ScanResult),
        Update(UpdateResult),
        Status(StatusResult),
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

    #[derive(Debug)]
    pub struct Daemon {
        version: String,
        rtp_on: bool,

        unix_path: PathBuf,
        config_path: PathBuf,
    }

    impl Daemon {
        pub fn new(unix_path: PathBuf, config_path: PathBuf) -> Self {
            Self {
                version: VERSION.to_string(),
                rtp_on: false,
                unix_path,
                config_path,
            }
        }

        pub async fn start(self: Self) -> Result<(), Box<dyn std::error::Error>> {
            let listener = UnixListener::bind(self.unix_path.clone())?;
            let me = Arc::new(self);

            loop {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let mut request = serde_json::Deserializer::from_reader(&socket);
                        let response = match Request::deserialize(&mut request) {
                            Ok(request) => match me.clone().handle_request(&request).await {
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
                        serde_json::to_writer(socket, &response).unwrap();
                    }
                    Err(e) => println!("accept function failed: {:?}", e),
                }
            }
        }

        pub async fn handle_request(
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

            println!("{:?}", yr_path.to_str());

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
