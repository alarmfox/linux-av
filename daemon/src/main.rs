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

    use std::{
        fs::File,
        io::{self, BufRead, BufReader, Cursor},
        os::unix::net::UnixListener,
        path::PathBuf,
    };

    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use tempfile::tempfile;
    use zip::ZipArchive;

    #[derive(Serialize, Deserialize)]
    enum Command {
        Scan { path: PathBuf, signature_only: bool },
        Status,
        Update,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Request {
        command: Command,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Response {
        status: u32,
        result: Option<ScanResult>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct ScanResult {
        threat: bool,
        intelligence: Option<Vec<YaraResult>>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct YaraResult {
        name: String,
        url: String,
        description: String,
    }
    #[derive(Debug)]
    pub struct Error {}

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

        pub async fn start(self: &Self) -> Result<(), Box<dyn std::error::Error>> {
            let listener = UnixListener::bind(self.unix_path.clone())?;

            loop {
                match listener.accept() {
                    Ok((socket, _)) => {
                        let mut request = serde_json::Deserializer::from_reader(&socket);
                        let request = Request::deserialize(&mut request).unwrap();
                        let response = self.handle_request(&request).await.unwrap();

                        serde_json::to_writer(socket, &response).unwrap();
                    }
                    Err(e) => println!("accept function failed: {:?}", e),
                }
            }
        }
        pub async fn handle_request(self: &Self, request: &Request) -> Result<Response, Error> {
            match &request.command {
                Command::Scan {
                    path,
                    signature_only,
                } => {
                    if path.is_dir() {
                        todo!();
                    }

                    let mut file = File::open(path).unwrap();
                    let mut sha256 = Sha256::new();
                    io::copy(&mut file, &mut sha256).unwrap();
                    let hash = sha256.finalize();
                    let hash = format!("{:x}", hash);

                    let is_threat = self.scan_sig(hash.as_str());

                    if !signature_only {
                        todo!();
                    }

                    Ok(Response {
                        status: 0,
                        result: Some(ScanResult {
                            threat: is_threat,
                            intelligence: None,
                        }),
                    })
                }
                Command::Update => {
                    let mut tempfile = tempfile().unwrap();
                    let response = reqwest::get(MB_SHA256_URL).await.unwrap();
                    let mut stream = Cursor::new(response.bytes().await.unwrap());

                    io::copy(&mut stream, &mut tempfile);

                    ZipArchive::new(tempfile)
                        .unwrap()
                        .extract(self.config_path.clone())
                        .unwrap();

                    Ok(Response {
                        status: 0,
                        result: None,
                    })
                }
                Command::Status => Ok(Response {
                    status: 0,
                    result: None,
                }),
            }
        }
        fn scan_sig(self: &Self, hash: &str) -> bool {
            let file = File::open(self.config_path.clone().join(MB_SHA256_FILE)).unwrap();

            let reader = BufReader::new(file);

            for line in reader.lines() {
                if let Ok(a) = line {
                    if a == hash {
                        return true;
                    }
                }
            }
            return false;
        }
    }
}
