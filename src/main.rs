//! Share a secret (e.g. an access token) with an AI agent over HTTPS.
//!
//! The secret is served on a random port over TLS with a freshly generated
//! self-signed certificate. The certificate's public key hash is pinned in the
//! printed `curl` command so the agent can't be tricked into talking to a
//! different server. Access is protected by a random one-time password that is
//! consumed by the first successful request, after which the server shuts down.
//! Too many failed attempts, or reaching the expiry time, also shut it down.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rcgen::PublicKeyData;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

const MAX_FAILED_ATTEMPTS: u32 = 5;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_EXPIRY: &str = "1h";

struct Args {
    host: String,
    expiry: Duration,
    expiry_label: String,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let args = parse_args();

    let secret = rpassword::prompt_password("Enter secret value: ")?;
    let secret = secret.trim_end_matches(['\r', '\n']).to_string();
    if secret.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret must not be empty",
        ));
    }

    let (tls_config, pin) = make_tls_config()?;

    // Port 0 asks the OS for a random free port.
    let listener = TcpListener::bind((args.host.as_str(), 0))?;
    let addr = listener.local_addr()?;
    let mut otp = Some(random_token()?);
    // When listening on all interfaces, 0.0.0.0 isn't reachable from other
    // machines, so advertise this machine's primary LAN address instead.
    let advertised = if addr.ip().is_unspecified() {
        SocketAddr::new(primary_local_ip().unwrap_or(addr.ip()), addr.port())
    } else {
        addr
    };
    let url = format!("https://{advertised}/secret");

    println!();
    println!("----- copy the prompt below to your AI agent -----");
    println!();
    println!(
        "A secret value has been shared with you over HTTPS. Fetch it exactly once with:\n\n\
         \x20   curl -sS --insecure --pinnedpubkey 'sha256//{pin}' -H 'Authorization: Bearer {otp}' {url}\n\n\
         The server uses a self-signed certificate. --insecure only skips CA validation; \
         --pinnedpubkey makes curl verify the server's exact public key and abort if it does \
         not match, so you are guaranteed to be talking to the right server. Keep both flags \
         as-is. The response body is the secret value (no trailing newline). The password is \
         single-use: the first successful request consumes it and the server then shuts \
         down, so store the value somewhere safe (e.g. an environment variable) instead of \
         fetching it again. The server expires {expiry} after this message was generated. \
         Do not print, log, or echo the secret value.",
        otp = otp.as_deref().unwrap(),
        expiry = args.expiry_label,
    );
    println!();
    println!("--------------------------------------------------");
    println!();
    eprintln!(
        "Waiting for a request on {addr}, expires in {} (Ctrl-C to cancel)...",
        args.expiry_label
    );

    let expiry = args.expiry;
    let label = args.expiry_label.clone();
    std::thread::spawn(move || {
        std::thread::sleep(expiry);
        eprintln!("Expired after {label} without sharing the secret. Exiting.");
        std::process::exit(3);
    });

    let mut failures = 0;
    for stream in listener.incoming() {
        let tcp = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept failed: {e}");
                continue;
            }
        };
        let peer = tcp.peer_addr().map(|a| a.to_string()).unwrap_or_default();
        let _ = tcp.set_read_timeout(Some(IO_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(IO_TIMEOUT));
        let conn = match rustls::ServerConnection::new(tls_config.clone()) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("TLS setup failed: {e}");
                continue;
            }
        };
        let mut tls = rustls::StreamOwned::new(conn, tcp);

        let outcome = handle(&mut tls, otp.as_deref().unwrap(), &secret);
        tls.conn.send_close_notify();
        let _ = tls.flush();

        match outcome {
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

/// Generates a fresh self-signed certificate (ECDSA P-256) and returns the TLS
/// config plus the base64 SHA-256 hash of its public key, in the format curl's
/// `--pinnedpubkey sha256//...` expects.
fn make_tls_config() -> io::Result<(Arc<rustls::ServerConfig>, String)> {
    let err = |e: &dyn std::fmt::Display| io::Error::other(e.to_string());

    let key = rcgen::KeyPair::generate().map_err(|e| err(&e))?;
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).map_err(|e| err(&e))?;
    let cert = params.self_signed(&key).map_err(|e| err(&e))?;

    let pin = base64::engine::general_purpose::STANDARD
        .encode(Sha256::digest(key.subject_public_key_info()));
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| err(&e))?
    .with_no_client_auth()
    .with_single_cert(vec![cert.der().clone()], key_der)
    .map_err(|e| err(&e))?;

    Ok((Arc::new(config), pin))
}

/// Finds the IP of the interface used for outbound traffic. Connecting a UDP
/// socket only selects a route; no packets are sent.
fn primary_local_ip() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?; // TEST-NET-1, never actually contacted
    let ip = socket.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

fn parse_args() -> Args {
    let mut args = std::env::args().skip(1);
    let mut host = "127.0.0.1".to_string();
    let mut expiry_label = DEFAULT_EXPIRY.to_string();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--public" => host = "0.0.0.0".to_string(),
            "--bind" | "-b" => host = args.next().unwrap_or_else(|| usage_and_exit()),
            "--expires" | "-e" => expiry_label = args.next().unwrap_or_else(|| usage_and_exit()),
            _ => usage_and_exit(),
        }
    }
    let expiry = parse_duration(&expiry_label).unwrap_or_else(|| {
        eprintln!("error: invalid duration {expiry_label:?} (examples: 90s, 15m, 1h, 2h30m, 1d)\n");
        usage_and_exit()
    });
    Args {
        host,
        expiry,
        expiry_label,
    }
}

/// Parses durations like `90`, `90s`, `15m`, `1h`, `2h30m` or `1d`. A bare
/// number means seconds. Zero is rejected.
fn parse_duration(s: &str) -> Option<Duration> {
    let mut total: u64 = 0;
    let mut num = String::new();
    for c in s.trim().chars() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86400,
            _ => return None,
        };
        let n: u64 = num.parse().ok()?;
        total = total.checked_add(n.checked_mul(unit)?)?;
        num.clear();
    }
    if !num.is_empty() {
        total = total.checked_add(num.parse().ok()?)?;
    }
    (total > 0).then(|| Duration::from_secs(total))
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage: agent-network-secret-share [--public | --bind HOST] [--expires DURATION]\n\n\
         Prompts for a secret and serves it once over HTTPS on a random port, protected\n\
         by a one-time password and a pinned self-signed certificate.\n\n\
         \x20 --public            listen on all network interfaces (same as --bind 0.0.0.0)\n\
         \x20 --bind HOST         listen on HOST (default: 127.0.0.1)\n\
         \x20 --expires DURATION  shut down after DURATION, e.g. 15m, 2h, 1d (default: {DEFAULT_EXPIRY})"
    );
    std::process::exit(64);
}

enum Outcome {
    Served,
    Unauthorized,
    Other,
}

fn handle<S: Read + Write>(stream: &mut S, otp: &str, secret: &str) -> Outcome {
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
fn read_request<S: Read>(stream: &mut S) -> io::Result<(String, String, Option<String>)> {
    let mut reader = BufReader::new((&mut *stream).take(MAX_HEADER_BYTES as u64));
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
            && name.trim().eq_ignore_ascii_case("authorization")
        {
            auth = Some(value.trim().to_string());
        }
    }
    Ok((method, path, auth))
}

fn respond<S: Write>(stream: &mut S, status: &str, body: &str) {
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

/// 32 random bytes (256 bits) from the operating system's CSPRNG, hex encoded.
/// Fails rather than falling back to a weaker source if the OS RNG errors.
fn random_token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Compares without leaking where the inputs differ through timing. Uses the
/// audited `subtle` crate so the compiler can't turn it into an early exit.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn token_is_256_bits_of_lowercase_hex() {
        let t = random_token().unwrap();
        assert_eq!(t.len(), 64);
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }

    #[test]
    fn tokens_are_unique_and_unbiased() {
        let tokens: Vec<String> = (0..1000).map(|_| random_token().unwrap()).collect();
        assert_eq!(tokens.iter().collect::<HashSet<_>>().len(), tokens.len());

        // Each of the 16 hex digits should appear about 64000/16 = 4000 times.
        let mut counts = [0u32; 16];
        for b in tokens.iter().flat_map(|t| t.bytes()) {
            counts[(b as char).to_digit(16).unwrap() as usize] += 1;
        }
        assert!(
            counts.iter().all(|&c| (3500..4500).contains(&c)),
            "{counts:?}"
        );
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("90"), Some(Duration::from_secs(90)));
        assert_eq!(parse_duration("15m"), Some(Duration::from_secs(900)));
        assert_eq!(parse_duration("1h"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_duration("2h30m"), Some(Duration::from_secs(9000)));
        assert_eq!(parse_duration("1d"), Some(Duration::from_secs(86400)));
        for bad in ["", "0", "0h", "h", "1x", "-1h", "1.5h"] {
            assert_eq!(parse_duration(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn constant_time_eq_matches_only_identical_input() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"abc"));
    }
}
