use std::{
    fs::{self, File},
    io::{self, BufRead, BufReader},
    os::unix::net::UnixListener,
    path::PathBuf,
};

use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tempfile::tempfile;
use zip::ZipArchive;

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // You can see how many times a particular flag or argument occurred
    // Note, only flags can have multiple occurrences
    match cli.verbose {
        0 => println!("Debug mode is off"),
        1 => println!("Debug mode is kind of on"),
        2 => println!("Debug mode is on"),
        _ => println!("Don't be crazy"),
    }

    fs::create_dir_all(&cli.config_dir).unwrap();
    let listener = UnixListener::bind(cli.unix_socket)?;

    loop {
        match listener.accept() {
            Ok((socket, _)) => {
                let mut request = serde_json::Deserializer::from_reader(&socket);
                let request = Request::deserialize(&mut request).unwrap();
                let response = handle_request(&cli.config_dir, &request);

                let response: Response = if let Err(e) = response {
                    Response {
                        status: 1,
                        error: Some(e),
                    }
                } else {
                    Response {
                        status: 0,
                        error: None,
                    }
                };

                serde_json::to_writer(socket, &response).unwrap();
            }
            Err(e) => println!("accept function failed: {:?}", e),
        }
    }
}

#[derive(Serialize, Deserialize)]
enum Command {
    Scan { path: PathBuf, signature_only: bool },
    Status,
    Update { force: bool },
}

#[derive(Serialize, Deserialize)]
struct Request {
    command: Command,
}

#[derive(Serialize)]
struct Response {
    status: u32,
    error: Option<Error>,
}

#[derive(Serialize)]
enum Error {
    UnsupportedOperation { reason: String },
    IllegalIOOperatiion,
}

fn handle_request(config_dir: &PathBuf, request: &Request) -> Result<(), Error> {
    match &request.command {
        Command::Scan {
            path,
            signature_only,
        } => {
            if path.is_dir() {
                return Err(Error::UnsupportedOperation {
                    reason: "Directory scanning not supported yet".to_string(),
                });
            }

            let mut file = File::open(path).unwrap();
            let mut sha256 = Sha256::new();
            io::copy(&mut file, &mut sha256).unwrap();
            let hash = sha256.finalize();
            let hash = format!("{:x}", hash);
            println!("hash: {}", hash);
            scan_sig(config_dir, hash.as_str());

            Ok(())
        }
        Command::Update { force } => {
            let url = "https://bazaar.abuse.ch/export/txt/sha256/full/";
            let mut tempfile = tempfile().unwrap();
            let _ = reqwest::blocking::get(url)
                .unwrap()
                .copy_to(&mut tempfile)
                .unwrap();

            ZipArchive::new(tempfile)
                .unwrap()
                .extract(config_dir)
                .unwrap();

            Ok(())
        }
        Command::Status => Ok(()),
    }
}

fn scan_sig(config_dir: &PathBuf, hash: &str) {
    let file = File::open(config_dir.join("full_sha256.txt")).unwrap();

    let reader = BufReader::new(file);

    for line in reader.lines() {
        if let Ok(a) = line {
            if a == hash {
                println!("found");
                break;
            }
        }
    }
}
