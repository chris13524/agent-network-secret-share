//! Share a secret (e.g. an access token) with an AI agent over HTTP.
//!
//! The secret is served on a random local port and protected by a randomly
//! generated one-time password. The password is consumed by the first
//! successful request, after which the server shuts down. Too many failed
//! attempts also shut the server down.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const MAX_FAILED_ATTEMPTS: u32 = 5;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let bind_host = parse_args();

    let secret = rpassword::prompt_password("Enter secret value: ")?;
    let secret = secret.trim_end_matches(['\r', '\n']).to_string();
    if secret.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "secret must not be empty"));
    }

    // Port 0 asks the OS for a random free port.
    let listener = TcpListener::bind((bind_host.as_str(), 0))?;
    let addr = listener.local_addr()?;
    let mut otp = Some(random_token()?);
    let url = format!("http://{}/secret", addr);

    println!();
    println!("----- copy the prompt below to your AI agent -----");
    println!();
    println!(
        "A secret value has been shared with you over HTTP. Fetch it exactly once with:\n\n\
         \x20   curl -s -H 'Authorization: Bearer {otp}' {url}\n\n\
         The response body is the secret value (no trailing newline). The password above \
         is single-use: the first successful request consumes it and the server then shuts \
         down, so store the value somewhere safe (e.g. an environment variable) instead of \
         fetching it again. Do not print, log, or echo the secret value.",
        otp = otp.as_deref().unwrap(),
        url = url,
    );
    println!();
    println!("--------------------------------------------------");
    println!();
    eprintln!("Waiting for a request on {addr} (Ctrl-C to cancel)...");

    let mut failures = 0;
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept failed: {e}");
                continue;
            }
        };
        let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();

        match handle(&mut stream, otp.as_deref().unwrap(), &secret) {
            Outcome::Served => {
                otp = None;
                eprintln!("Secret delivered to {peer}; one-time password consumed. Exiting.");
                break;
            }
            Outcome::Unauthorized => {
                failures += 1;
                eprintln!(
                    "Rejected unauthorized request from {peer} ({failures}/{MAX_FAILED_ATTEMPTS})."
                );
                if failures >= MAX_FAILED_ATTEMPTS {
                    eprintln!("Too many failed attempts. Exiting without sharing the secret.");
                    std::process::exit(2);
                }
            }
            Outcome::Other => {}
        }
    }
    debug_assert!(otp.is_none());
    Ok(())
}

/// Returns the host to bind to. Defaults to loopback only.
fn parse_args() -> String {
    let mut args = std::env::args().skip(1);
    let mut host = "127.0.0.1".to_string();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" | "-b" => match args.next() {
                Some(h) => host = h,
                None => usage_and_exit(),
            },
            "--help" | "-h" => usage_and_exit(),
            _ => usage_and_exit(),
        }
    }
    host
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage: agent-network-secret-share [--bind HOST]\n\n\
         Prompts for a secret and serves it once on a random port, protected by a\n\
         one-time password. HOST defaults to 127.0.0.1."
    );
    std::process::exit(64);
}

enum Outcome {
    Served,
    Unauthorized,
    Other,
}

fn handle(stream: &mut TcpStream, otp: &str, secret: &str) -> Outcome {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    let (method, path, auth) = match read_request(stream) {
        Ok(r) => r,
        Err(_) => {
            respond(stream, "400 Bad Request", "bad request\n");
            return Outcome::Other;
        }
    };

    if path != "/secret" {
        respond(stream, "404 Not Found", "not found\n");
        return Outcome::Other;
    }
    if method != "GET" {
        respond(stream, "405 Method Not Allowed", "method not allowed\n");
        return Outcome::Other;
    }

    let presented = auth
        .as_deref()
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");
    if constant_time_eq(presented.as_bytes(), otp.as_bytes()) {
        respond(stream, "200 OK", secret);
        Outcome::Served
    } else {
        respond(stream, "401 Unauthorized", "unauthorized\n");
        Outcome::Unauthorized
    }
}

/// Reads the request line and headers. Returns (method, path, authorization header).
fn read_request(stream: &mut TcpStream) -> io::Result<(String, String, Option<String>)> {
    let mut reader = BufReader::new(stream.take(MAX_HEADER_BYTES as u64));
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "malformed request");

    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or_else(bad)?.to_string();
    let path = parts.next().ok_or_else(bad)?.to_string();

    let mut auth = None;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(bad()); // EOF or header limit reached before end of headers
        }
        let header = line.trim_end_matches(['\r', '\n']);
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.trim().eq_ignore_ascii_case("authorization") {
                auth = Some(value.trim().to_string());
            }
    }
    Ok((method, path, auth))
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// 32 random bytes from the OS CSPRNG, hex encoded.
fn random_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
