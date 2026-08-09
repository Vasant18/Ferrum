//! Authentication and authorization middleware.
//!
//! Two separate layers, because they answer two different questions and return
//! two different statuses:
//!
//! - **Auth** — *who are you?* Checks credentials, sets `ctx.identity`, and on
//!   failure returns **401** with a `WWW-Authenticate` challenge.
//! - **Authz** — *may you?* Checks the established identity against an
//!   allowlist and on failure returns **403**.
//!
//! Collapsing them would force one status to serve both meanings, and 401-vs-
//! 403 is a real distinction: 401 invites the client to retry with credentials,
//! 403 tells an already-authenticated client to stop asking.

use super::{Decision, Middleware, ReqCtx, Rejection};
use crate::http::{self, RequestHead};

/// Decode standard base64 (alphabet `A–Za–z0–9+/`, `=` padding). Returns
/// `None` on any invalid input rather than being lenient — a malformed
/// credential is a 401, and leniency in a decoder that guards auth is exactly
/// how bypasses happen.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.as_bytes();
    // Canonical base64 is always a multiple of 4 (with padding). Reject the
    // rest outright rather than guessing at the intent.
    if s.is_empty() || s.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let last_chunk = s.len() / 4 - 1;
    for (i, chunk) in s.chunks(4).enumerate() {
        let pad = chunk.iter().filter(|&&b| b == b'=').count();
        if pad > 2 {
            return None;
        }
        // Padding is only legal in the FINAL chunk. A padded chunk followed by
        // more data (e.g. "AA==AAAA") is non-canonical base64 — reject it rather
        // than decode it, so the function's contract ("= is only trailing
        // padding") actually holds. Without this an earlier `=`-bearing group
        // would silently produce bytes.
        if pad > 0 && i != last_chunk {
            return None;
        }
        // Within the (final) chunk, `=` may only be trailing: a `=` among the
        // data sextets is malformed.
        if chunk[..4 - pad].iter().any(|&b| b == b'=') {
            return None;
        }
        let mut n = 0u32;
        for &b in &chunk[..4 - pad] {
            n = (n << 6) | val(b)? as u32;
        }
        // Shift in the sextets the padding stands for, so the high bytes land
        // in the right place.
        n <<= 6 * pad;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Compare two byte slices without early-exit on the first differing byte.
///
/// A plain `==` on secrets short-circuits at the first mismatch, so response
/// timing leaks the length and matching prefix of the secret one byte at a
/// time. Here length is *not* secret (credentials differ in length by design),
/// so we bail on a length mismatch; within equal lengths we OR every byte
/// difference together so the running time does not depend on *where* the
/// mismatch is.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// One accepted credential. Bearer carries a `label` so `ctx.identity` gets a
/// human name rather than the raw token.
pub enum Credential {
    Basic { user: String, pass: String },
    Bearer { token: String, label: String },
}

/// Checks the `Authorization` header against a set of accepted credentials.
pub struct Auth {
    pub creds: Vec<Credential>,
    pub realm: String,
}

impl Auth {
    /// The single 401 every failure path returns. Identical bytes regardless of
    /// *why* it failed (no such user vs. wrong password vs. no header): telling
    /// them apart would be a username oracle.
    fn reject_401(&self) -> Decision {
        Decision::Reject(Rejection {
            status: 401,
            reason: "Unauthorized",
            headers: vec![(
                "WWW-Authenticate".to_string(),
                format!("Basic realm=\"{}\"", self.realm),
            )],
            body: "401 Unauthorized\n".to_string(),
        })
    }
}

impl Middleware for Auth {
    fn name(&self) -> &'static str {
        "auth"
    }

    fn on_request(&self, req: &mut RequestHead, ctx: &mut ReqCtx) -> Decision {
        let Some(authz) = http::header(&req.headers, "authorization") else {
            return self.reject_401();
        };

        // Split "Scheme credentials" on the first space.
        let (scheme, cred) = match authz.split_once(' ') {
            Some((s, c)) => (s, c.trim()),
            None => return self.reject_401(),
        };

        if scheme.eq_ignore_ascii_case("basic") {
            let Some(decoded) = base64_decode(cred) else {
                return self.reject_401();
            };
            // The decoded payload is `user:pass`; split on the FIRST colon so a
            // password may itself contain colons.
            let Some(colon) = decoded.iter().position(|&b| b == b':') else {
                return self.reject_401();
            };
            let (user, pass) = decoded.split_at(colon);
            let pass = &pass[1..]; // drop the colon
            for c in &self.creds {
                if let Credential::Basic { user: u, pass: p } = c {
                    // Compare both fields in constant time. `&` not `&&` so we
                    // don't short-circuit on the user check and reintroduce a
                    // timing signal on the password.
                    if ct_eq(u.as_bytes(), user) & ct_eq(p.as_bytes(), pass) {
                        ctx.identity = Some(u.clone());
                        return Decision::Continue;
                    }
                }
            }
            return self.reject_401();
        }

        if scheme.eq_ignore_ascii_case("bearer") {
            for c in &self.creds {
                if let Credential::Bearer { token, label } = c {
                    if ct_eq(token.as_bytes(), cred.as_bytes()) {
                        ctx.identity = Some(label.clone());
                        return Decision::Continue;
                    }
                }
            }
            return self.reject_401();
        }

        // Any other scheme (Digest, Negotiate, …) is unsupported → 401.
        self.reject_401()
    }
}

/// Checks `ctx.identity` (set by `Auth`) against an allowlist.
pub struct Authz {
    pub allowed: Vec<String>,
}

impl Middleware for Authz {
    fn name(&self) -> &'static str {
        "authz"
    }

    fn on_request(&self, _req: &mut RequestHead, ctx: &mut ReqCtx) -> Decision {
        // A route with `require-user` and no `auth=` is rejected at startup, so
        // `identity == None` is unreachable in a valid config. We still handle
        // it defensively as a 403: if it somehow happens, refusing is safe,
        // and a 401 here would loop a client that already sent no credentials.
        let ok = match &ctx.identity {
            Some(id) => self.allowed.iter().any(|a| a == id),
            None => false,
        };
        if ok {
            Decision::Continue
        } else {
            Decision::Reject(Rejection {
                status: 403,
                reason: "Forbidden",
                headers: vec![],
                body: "403 Forbidden\n".to_string(),
            })
        }
    }
}

// Auth and Authz are request-only: they never need to touch the response, so
// they inherit the trait's no-op `on_response`.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{RequestHead, Version};

    fn base64_encode_for_test(data: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(T[((n >> 18) & 63) as usize] as char);
            out.push(T[((n >> 12) & 63) as usize] as char);
            out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
            out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
        }
        out
    }
    fn basic_header(user: &str, pass: &str) -> String {
        format!("Basic {}", base64_encode_for_test(format!("{user}:{pass}").as_bytes()))
    }
    fn req(auth: Option<&str>) -> RequestHead {
        let headers = auth
            .map(|a| vec![("Authorization".into(), a.into())])
            .unwrap_or_default();
        RequestHead {
            method: "GET".into(),
            target: "/".into(),
            version: Version::Http11,
            headers,
        }
    }
    fn ctx() -> ReqCtx {
        ReqCtx::new("127.0.0.1:1".parse().unwrap(), "GET".into(), "/".into(), None)
    }
    fn basic_auth() -> Auth {
        Auth {
            creds: vec![Credential::Basic {
                user: "admin".into(),
                pass: "s3cret".into(),
            }],
            realm: "ferrum".into(),
        }
    }

    #[test]
    fn valid_basic_passes_and_sets_identity() {
        let mut c = ctx();
        let mut r = req(Some(&basic_header("admin", "s3cret")));
        assert!(matches!(basic_auth().on_request(&mut r, &mut c), Decision::Continue));
        assert_eq!(c.identity.as_deref(), Some("admin"));
    }

    #[test]
    fn wrong_password_401() {
        let mut c = ctx();
        let mut r = req(Some(&basic_header("admin", "wrong")));
        match basic_auth().on_request(&mut r, &mut c) {
            Decision::Reject(Rejection { status, .. }) => assert_eq!(status, 401),
            _ => panic!("expected 401"),
        }
    }

    #[test]
    fn unknown_user_401_no_oracle() {
        let mut c = ctx();
        let mut r = req(Some(&basic_header("ghost", "s3cret")));
        let Decision::Reject(bad_user) = basic_auth().on_request(&mut r, &mut c) else {
            panic!()
        };
        let mut c2 = ctx();
        let mut r2 = req(Some(&basic_header("admin", "wrong")));
        let Decision::Reject(bad_pass) = basic_auth().on_request(&mut r2, &mut c2) else {
            panic!()
        };
        assert_eq!(bad_user.status, bad_pass.status);
        assert_eq!(bad_user.body, bad_pass.body);
    }

    #[test]
    fn missing_auth_401_with_challenge() {
        let mut c = ctx();
        let mut r = req(None);
        match basic_auth().on_request(&mut r, &mut c) {
            Decision::Reject(rej) => {
                assert_eq!(rej.status, 401);
                let chal = rej
                    .headers
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case("www-authenticate"));
                assert!(chal.unwrap().1.contains("realm=\"ferrum\""));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn malformed_base64_401_not_panic() {
        let mut c = ctx();
        let mut r = req(Some("Basic !!!not base64!!!"));
        assert!(matches!(basic_auth().on_request(&mut r, &mut c), Decision::Reject(_)));
    }

    #[test]
    fn basic_payload_without_colon_401() {
        let mut c = ctx();
        let mut r = req(Some(&format!("Basic {}", base64_encode_for_test(b"nocolon"))));
        assert!(matches!(basic_auth().on_request(&mut r, &mut c), Decision::Reject(_)));
    }

    #[test]
    fn wrong_scheme_401() {
        let mut c = ctx();
        let mut r = req(Some("Bearer sometoken"));
        assert!(matches!(basic_auth().on_request(&mut r, &mut c), Decision::Reject(_)));
    }

    #[test]
    fn valid_bearer_passes() {
        let auth = Auth {
            creds: vec![Credential::Bearer {
                token: "tok123".into(),
                label: "svc".into(),
            }],
            realm: "ferrum".into(),
        };
        let mut c = ctx();
        let mut r = req(Some("Bearer tok123"));
        assert!(matches!(auth.on_request(&mut r, &mut c), Decision::Continue));
        assert_eq!(c.identity.as_deref(), Some("svc"));
        let mut c2 = ctx();
        let mut r2 = req(Some("Bearer wrong"));
        assert!(matches!(auth.on_request(&mut r2, &mut c2), Decision::Reject(_)));
    }

    #[test]
    fn base64_decoder_roundtrip_and_rejects_garbage() {
        assert_eq!(base64_decode(&base64_encode_for_test(b"hello")).unwrap(), b"hello");
        assert_eq!(base64_decode(&base64_encode_for_test(b"any:pw")).unwrap(), b"any:pw");
        assert!(base64_decode("bad!char").is_none());
        assert!(base64_decode("====").is_none());
        // Non-canonical: padding before the final chunk must be rejected, not
        // silently decoded (the function's contract is "= is trailing only").
        assert!(base64_decode("AA==AAAA").is_none());
        assert!(base64_decode("QQ==QQ==").is_none());
        // A `=` in the middle of the final chunk's data is still rejected.
        assert!(base64_decode("A=AA").is_none());
    }

    #[test]
    fn ct_eq_correctness() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn authz_allows_and_denies_403() {
        let authz = Authz {
            allowed: vec!["admin".into()],
        };
        let mut c = ctx();
        c.identity = Some("admin".into());
        assert!(matches!(authz.on_request(&mut req(None), &mut c), Decision::Continue));

        let mut c2 = ctx();
        c2.identity = Some("intern".into());
        match authz.on_request(&mut req(None), &mut c2) {
            Decision::Reject(Rejection { status, .. }) => assert_eq!(status, 403),
            _ => panic!("expected 403, not 401 — authenticated but not permitted"),
        }
    }
}
