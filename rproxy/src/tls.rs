//! Level 8 — TLS termination and mutual TLS.
//!
//! This module is the *only* place in the crate that talks to a crypto library,
//! and that boundary is deliberate. Every other level of this course builds its
//! subsystem from primitives — the router's matcher, the balancer's hash ring,
//! the limiter's token bucket, the pool's LIFO stack. Certificate parsing and
//! TLS state machines are the documented exception: rolling them yourself is
//! this level's named mistake #1, because the failure mode is not a bug you can
//! see in a test, it is a silent loss of confidentiality.
//!
//! What we *do* own is everything around the handshake: where it runs (inside
//! the per-connection task, never the accept loop — see `main.rs`), how long it
//! may take (`TLS_HANDSHAKE_TIMEOUT`), and what identity it must present
//! (`ClientAuth`).
//!
//! ## Termination, in one diagram
//!
//! ```text
//! client ==== TLS (encrypted) ====> [ferrum: decrypt] ---- plaintext ----> backend
//!                                          |
//!                                   cert + private key
//!                                    live here only
//! ```
//!
//! The proxy holds the keys, performs the handshake, and decrypts. Backends
//! receive plain HTTP. This is what lets one IP serve certificates for many
//! domains (via SNI, which the client sends in cleartext), and it is *required*
//! for an L7 proxy in any case: you cannot route on a path or inspect a header
//! you cannot read.
//!
//! Everything Levels 1–7 built works over TLS **unchanged**, because Level 1
//! made `Conn<S>` generic over `S: AsyncRead + AsyncWrite + Unpin` instead of
//! concrete over `TcpStream`, and `tokio_rustls::server::TlsStream` implements
//! both. Seven levels later, that one decision is the whole of this level's
//! integration cost.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

/// Deadline for a client to complete the TLS handshake.
///
/// The TLS-layer analogue of Level 1's `HEAD_READ_TIMEOUT`, and not optional.
/// Without it, slowloris simply moves one layer down: a client that opens a
/// connection and never finishes its handshake is holding a socket on which no
/// request head will *ever* be read, so the head deadline never arms. The
/// connection would sit there until the kernel gave up.
///
/// 10s is deliberately tighter than the 30s head deadline. A handshake is a
/// fixed, small number of round trips with no user think-time in it; anything
/// slower than this is a broken client or an attack, not a slow one.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How strictly the proxy demands a client certificate.
///
/// Normal TLS authenticates the *server* to the client. mTLS adds the reverse
/// direction: the client must present a certificate we validate against a
/// trusted CA. It is authentication without passwords or tokens, at the
/// transport layer — rare for humans-with-browsers, heavily used for
/// service-to-service traffic (mesh sidecars, internal APIs, partner links).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ClientAuth {
    /// No client certificate requested. The default: mTLS is opt-in because
    /// turning it on without the fleet being ready is an outage.
    #[default]
    Off,
    /// Request a certificate and validate it if presented, but admit clients
    /// that present none.
    ///
    /// This mode exists because it is the only safe migration path onto mTLS:
    /// enable it, watch the logs to learn which callers actually present certs,
    /// *then* flip to `Required`. Going straight to `Required` on a live
    /// listener drops every client that has not been rolled out yet.
    Optional,
    /// Require a valid client certificate; reject the handshake otherwise.
    Required,
}

impl ClientAuth {
    /// Parse the `--tls-client-auth` value. Unknown values are a startup error
    /// rather than a silent fallback: quietly downgrading a misspelled
    /// `requried` to `Off` would disable client authentication on a listener
    /// whose operator believes it is enforced.
    pub fn parse(s: &str) -> io::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "off" | "none" => Ok(ClientAuth::Off),
            "optional" => Ok(ClientAuth::Optional),
            "required" | "require" => Ok(ClientAuth::Required),
            other => Err(bad(format!(
                "unknown --tls-client-auth {other:?} (expected off, optional, or required)"
            ))),
        }
    }

    /// Whether this mode needs a CA bundle to validate against.
    pub fn needs_ca(self) -> bool {
        matches!(self, ClientAuth::Optional | ClientAuth::Required)
    }
}

/// Everything the listener needs to terminate TLS, as gathered from the CLI.
///
/// Kept as plain paths rather than loaded material so that argument parsing
/// stays pure and the "did the operator ask for TLS at all?" question is a
/// simple `Option` at the call site.
#[derive(Clone, Debug, Default)]
pub struct TlsArgs {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub client_ca: Option<PathBuf>,
    pub client_auth: ClientAuth,
}

impl TlsArgs {
    /// True once any TLS flag has been supplied.
    pub fn requested(&self) -> bool {
        self.cert.is_some()
            || self.key.is_some()
            || self.client_ca.is_some()
            || self.client_auth != ClientAuth::Off
    }

    /// Validate the combination and build the rustls config, or return `None`
    /// when TLS was never requested (the plaintext listener stays the default —
    /// this is a learning proxy, and `rproxy LISTEN BACKEND` must keep working
    /// exactly as it did in Level 1).
    ///
    /// Every incoherent combination is rejected here, at startup, with exit 1 —
    /// the same guardrail discipline Level 5 used for protected headers and
    /// Level 6 for `require-user` without `auth=`. A proxy that boots into a
    /// half-configured TLS state is worse than one that refuses to boot.
    pub fn build(&self) -> io::Result<Option<Arc<ServerConfig>>> {
        if !self.requested() {
            return Ok(None);
        }
        let (cert, key) = match (&self.cert, &self.key) {
            (Some(c), Some(k)) => (c, k),
            (Some(_), None) => return Err(bad("--tls-cert requires --tls-key".into())),
            (None, Some(_)) => return Err(bad("--tls-key requires --tls-cert".into())),
            (None, None) => {
                return Err(bad(
                    "--tls-client-auth/--tls-client-ca require --tls-cert and --tls-key".into(),
                ))
            }
        };
        if self.client_auth.needs_ca() && self.client_ca.is_none() {
            return Err(bad(format!(
                "--tls-client-auth {:?} requires --tls-client-ca (there is nothing to validate \
                 client certificates against without it)",
                self.client_auth
            )));
        }
        // A CA bundle with client auth left off would be loaded, never
        // consulted, and give the operator a false sense of enforcement.
        if self.client_ca.is_some() && !self.client_auth.needs_ca() {
            return Err(bad(
                "--tls-client-ca given without --tls-client-auth optional|required (the CA would \
                 never be consulted)"
                    .into(),
            ));
        }
        build_server_config(cert, key, self.client_ca.as_deref(), self.client_auth).map(Some)
    }
}

/// Assemble a `ServerConfig` from PEM files on disk.
///
/// Protocol versions are rustls's safe defaults — TLS 1.3 and 1.2, and there is
/// deliberately no knob to go lower, because rustls does not implement SSLv3 or
/// TLS 1.0/1.1 at all. That absence is a feature: the knowledge base's stated
/// theme for this level is "the config a lazy user gets must be the safe one,"
/// and the strongest version of that is a config where the unsafe option cannot
/// be typed.
pub fn build_server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
    client_auth: ClientAuth,
) -> io::Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    warn_if_key_is_readable(key_path);

    // With `default-features = false` there is no process-wide default crypto
    // provider installed, so it is passed explicitly. That is the intended
    // trade: naming the provider in one place beats a global install whose
    // absence surfaces as a runtime panic on the first handshake.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| bad(format!("tls: {e}")))?;

    let builder = match client_auth {
        ClientAuth::Off => builder.with_no_client_auth(),
        mode => {
            let ca = client_ca_path.expect("validated by TlsArgs::build");
            let roots = load_root_store(ca)?;
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots));
            let verifier = if mode == ClientAuth::Optional {
                verifier.allow_unauthenticated()
            } else {
                verifier
            };
            let verifier = verifier
                .build()
                .map_err(|e| bad(format!("tls: bad client CA bundle {}: {e}", ca.display())))?;
            builder.with_client_cert_verifier(verifier)
        }
    };

    let mut config = builder
        .with_single_cert(certs, key)
        // The overwhelmingly common cause here is a cert/key pair that do not
        // belong together, so the message says so rather than echoing a raw
        // library error the operator cannot act on.
        .map_err(|e| {
            bad(format!(
                "tls: certificate {} and key {} do not form a usable pair: {e}",
                cert_path.display(),
                key_path.display()
            ))
        })?;

    // Advertise HTTP/1.1 only. This proxy speaks exactly one protocol, and
    // saying so in the handshake is more honest than letting a client negotiate
    // h2 and then discover we cannot parse it. (HTTP/2 is not on this course's
    // 14-level map; if it ever arrives, this is the line that changes.)
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Read a PEM certificate chain. An empty file is an error, not an empty chain:
/// a `ServerConfig` with no certificate cannot complete a handshake, and failing
/// here names the file instead of failing later with a generic TLS error.
fn load_certs(path: &Path) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut rd = BufReader::new(open(path, "certificate")?);
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<_, _>>()
        .map_err(|e| bad(format!("tls: bad certificate PEM {}: {e}", path.display())))?;
    if certs.is_empty() {
        return Err(bad(format!(
            "tls: no CERTIFICATE block found in {}",
            path.display()
        )));
    }
    Ok(certs)
}

/// Read a PEM private key, accepting PKCS#8, PKCS#1 (RSA), or SEC1 (EC) — the
/// three encodings a real operator's key file might arrive in. `private_key`
/// handles the demultiplexing; we only add a filename to the error.
fn load_private_key(path: &Path) -> io::Result<PrivateKeyDer<'static>> {
    let mut rd = BufReader::new(open(path, "private key")?);
    rustls_pemfile::private_key(&mut rd)
        .map_err(|e| bad(format!("tls: bad private key PEM {}: {e}", path.display())))?
        .ok_or_else(|| {
            bad(format!(
                "tls: no PRIVATE KEY block found in {}",
                path.display()
            ))
        })
}

/// Build the trust anchor set for client-certificate validation.
///
/// A partially-loaded bundle is rejected rather than tolerated: if 3 of 4 CAs
/// parse, silently proceeding means clients issued by the fourth are refused
/// with a handshake error that looks nothing like "your CA bundle is corrupt."
fn load_root_store(path: &Path) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let mut rd = BufReader::new(open(path, "client CA bundle")?);
    let cas: Vec<_> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<_, _>>()
        .map_err(|e| bad(format!("tls: bad client CA PEM {}: {e}", path.display())))?;
    if cas.is_empty() {
        return Err(bad(format!(
            "tls: no CERTIFICATE block found in client CA bundle {}",
            path.display()
        )));
    }
    let total = cas.len();
    let (added, ignored) = roots.add_parsable_certificates(cas);
    if ignored > 0 {
        return Err(bad(format!(
            "tls: {ignored} of {total} certificates in {} are not valid trust anchors",
            path.display()
        )));
    }
    debug_assert_eq!(added, total);
    Ok(roots)
}

/// Open a file, naming *what* it was in the error. `No such file or directory`
/// with no other context is a poor startup message when three different paths
/// could have produced it.
fn open(path: &Path, what: &str) -> io::Result<File> {
    File::open(path).map_err(|e| bad(format!("tls: cannot read {what} {}: {e}", path.display())))
}

/// Warn — but do not refuse — when a private key is readable beyond its owner.
///
/// "Private keys readable by the world" is on this level's list of common
/// mistakes, so silence would be wrong. A hard failure would also be wrong: key
/// material is legitimately delivered group-readable by plenty of secret
/// managers and init systems, and a proxy that refuses to start on a permission
/// bit it merely dislikes is a proxy operators route around. Warn loudly, start
/// anyway.
#[cfg(unix)]
fn warn_if_key_is_readable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mode = meta.permissions().mode() & 0o077;
        if mode != 0 {
            crate::warn!(
                "private key {} is mode {:o} — readable beyond its owner; \
                 chmod 600 it",
                path.display(),
                meta.permissions().mode() & 0o777
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_key_is_readable(_path: &Path) {}

fn bad(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_auth_parses_accepted_spellings() {
        assert_eq!(ClientAuth::parse("off").unwrap(), ClientAuth::Off);
        assert_eq!(ClientAuth::parse("none").unwrap(), ClientAuth::Off);
        assert_eq!(ClientAuth::parse("optional").unwrap(), ClientAuth::Optional);
        assert_eq!(ClientAuth::parse("required").unwrap(), ClientAuth::Required);
        assert_eq!(ClientAuth::parse("require").unwrap(), ClientAuth::Required);
        // Case-insensitive, like the rest of the CLI's enum-ish values.
        assert_eq!(ClientAuth::parse("REQUIRED").unwrap(), ClientAuth::Required);
    }

    /// A typo must not silently disable client authentication.
    #[test]
    fn client_auth_rejects_unknown() {
        assert!(ClientAuth::parse("requried").is_err());
        assert!(ClientAuth::parse("yes").is_err());
        assert!(ClientAuth::parse("").is_err());
    }

    #[test]
    fn needs_ca_only_for_verifying_modes() {
        assert!(!ClientAuth::Off.needs_ca());
        assert!(ClientAuth::Optional.needs_ca());
        assert!(ClientAuth::Required.needs_ca());
    }

    /// No TLS flags at all must stay plaintext — every Level 1–7 invocation
    /// depends on this.
    #[test]
    fn no_tls_flags_builds_nothing() {
        let args = TlsArgs::default();
        assert!(!args.requested());
        assert!(args.build().unwrap().is_none());
    }

    #[test]
    fn cert_without_key_is_a_startup_error() {
        let args = TlsArgs {
            cert: Some(PathBuf::from("/nonexistent/c.pem")),
            ..Default::default()
        };
        assert!(args.requested());
        let e = args.build().unwrap_err().to_string();
        assert!(e.contains("--tls-key"), "unexpected message: {e}");
    }

    #[test]
    fn key_without_cert_is_a_startup_error() {
        let args = TlsArgs {
            key: Some(PathBuf::from("/nonexistent/k.pem")),
            ..Default::default()
        };
        let e = args.build().unwrap_err().to_string();
        assert!(e.contains("--tls-cert"), "unexpected message: {e}");
    }

    /// mTLS with nothing to validate against would accept any certificate that
    /// parses. That must not be reachable.
    #[test]
    fn client_auth_without_ca_is_a_startup_error() {
        let args = TlsArgs {
            cert: Some(PathBuf::from("/nonexistent/c.pem")),
            key: Some(PathBuf::from("/nonexistent/k.pem")),
            client_auth: ClientAuth::Required,
            client_ca: None,
        };
        let e = args.build().unwrap_err().to_string();
        assert!(e.contains("--tls-client-ca"), "unexpected message: {e}");
    }

    /// The inverse trap: a CA that is loaded but never consulted reads as
    /// enforcement to whoever wrote the config.
    #[test]
    fn ca_without_client_auth_is_a_startup_error() {
        let args = TlsArgs {
            cert: Some(PathBuf::from("/nonexistent/c.pem")),
            key: Some(PathBuf::from("/nonexistent/k.pem")),
            client_ca: Some(PathBuf::from("/nonexistent/ca.pem")),
            client_auth: ClientAuth::Off,
        };
        let e = args.build().unwrap_err().to_string();
        assert!(e.contains("never be consulted"), "unexpected message: {e}");
    }

    /// Client auth alone, with no server identity, is incoherent — and the
    /// message must point at the missing cert rather than the CA.
    #[test]
    fn client_auth_alone_names_the_missing_cert() {
        let args = TlsArgs {
            client_auth: ClientAuth::Optional,
            ..Default::default()
        };
        let e = args.build().unwrap_err().to_string();
        assert!(e.contains("--tls-cert"), "unexpected message: {e}");
    }

    #[test]
    fn missing_cert_file_names_the_path() {
        let args = TlsArgs {
            cert: Some(PathBuf::from("/nonexistent/ferrum-test-cert.pem")),
            key: Some(PathBuf::from("/nonexistent/ferrum-test-key.pem")),
            ..Default::default()
        };
        let e = args.build().unwrap_err().to_string();
        assert!(e.contains("ferrum-test-cert.pem"), "unexpected message: {e}");
        assert!(e.contains("certificate"), "unexpected message: {e}");
    }

    /// A file that exists but holds no PEM block must fail naming the file,
    /// not with a generic TLS error at first handshake.
    #[test]
    fn empty_cert_file_is_rejected() {
        let dir = std::env::temp_dir();
        let path = dir.join("ferrum-empty-cert.pem");
        std::fs::write(&path, b"not a pem file\n").unwrap();
        let e = load_certs(&path).unwrap_err().to_string();
        assert!(e.contains("no CERTIFICATE block"), "unexpected: {e}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_key_file_is_rejected() {
        let dir = std::env::temp_dir();
        let path = dir.join("ferrum-empty-key.pem");
        std::fs::write(&path, b"nothing here\n").unwrap();
        let e = load_private_key(&path).unwrap_err().to_string();
        assert!(e.contains("no PRIVATE KEY block"), "unexpected: {e}");
        let _ = std::fs::remove_file(&path);
    }

    /// The handshake deadline must be tighter than the head deadline: a
    /// handshake has no user think-time in it.
    #[test]
    fn handshake_deadline_is_tighter_than_head_deadline() {
        assert!(TLS_HANDSHAKE_TIMEOUT < Duration::from_secs(30));
    }
}
