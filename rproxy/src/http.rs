//! HTTP/1.1 message-head parsing and body framing, from first principles.
//!
//! TCP hands us an undifferentiated byte stream. Everything in this module
//! exists to answer two questions about that stream:
//!   1. Where does the message head (request/status line + headers) end?
//!   2. Given the head, how do we know where the body ends?

use std::io;

/// Hard cap on the head (request line + all headers). Anything larger is
/// almost certainly an attack or a broken client, and unbounded buffering
/// of unauthenticated input is how proxies get OOM-killed.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// A parsed request head. Header values borrow nothing: for Level 1 we pay
/// the allocation cost for owned Strings and keep lifetimes out of the
/// picture. (Zero-copy parsing is a Level 7 optimization.)
#[derive(Debug)]
pub struct RequestHead {
    pub method: String,
    /// Origin-form target, e.g. "/api/users?page=2".
    pub target: String,
    pub version: Version,
    pub headers: Vec<(String, String)>,
}

/// A parsed response head from the backend.
#[derive(Debug)]
pub struct ResponseHead {
    pub version: Version,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    Http10,
    Http11,
}

impl Version {
    pub fn as_str(&self) -> &'static str {
        match self {
            Version::Http10 => "HTTP/1.0",
            Version::Http11 => "HTTP/1.1",
        }
    }
}

/// How the message body is delimited on the wire. Deciding this correctly is
/// the single most security-sensitive piece of parsing a proxy does: when a
/// proxy and a backend disagree about where a body ends, the leftover bytes
/// become a smuggled second request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    /// No body at all (e.g. GET without length, or a 204/304 response).
    None,
    /// Exactly N bytes follow the head.
    Length(u64),
    /// Hex-sized chunks until a zero-size chunk ("0\r\n\r\n").
    Chunked,
    /// Body runs until the peer closes the connection. Only legal for
    /// responses (a request delimited by close could never be answered).
    UntilClose,
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// Locate the end of the head: the byte index just past the first
/// `\r\n\r\n`. Returns None if the terminator hasn't arrived yet, which
/// tells the caller to read more bytes and try again.
pub fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn parse_version(s: &str) -> io::Result<Version> {
    match s {
        "HTTP/1.1" => Ok(Version::Http11),
        "HTTP/1.0" => Ok(Version::Http10),
        other => Err(invalid(format!("unsupported HTTP version: {other}"))),
    }
}

/// Split raw head bytes into lines and parse `Name: value` pairs.
/// Shared by request and response parsing.
fn parse_header_lines(lines: std::str::Lines<'_>) -> io::Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        // Header field: name ":" OWS value OWS. A missing colon is a
        // malformed message; forwarding it would make us complicit in
        // whatever parser-confusion it is trying to cause.
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid(format!("malformed header line: {line:?}")))?;
        if name.is_empty() || name.contains(' ') {
            // "Host : x" (space before colon) is rejected by RFC 9112 §5.1
            // precisely because lenient parsers disagree about it.
            return Err(invalid(format!("malformed header name: {name:?}")));
        }
        headers.push((name.to_string(), value.trim().to_string()));
    }
    Ok(headers)
}

/// Parse a complete request head (everything up to and including the blank
/// line). `raw` must be exactly the head as located by `find_head_end`.
pub fn parse_request_head(raw: &[u8]) -> io::Result<RequestHead> {
    // The head is required to be ASCII-compatible; reject anything that
    // isn't valid UTF-8 rather than guessing.
    let text = std::str::from_utf8(raw).map_err(|_| invalid("head is not valid UTF-8"))?;
    let mut lines = text.lines();
    let request_line = lines.next().ok_or_else(|| invalid("empty request head"))?;

    // Request line: METHOD SP request-target SP HTTP-version
    let mut parts = request_line.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None) if !m.is_empty() && !t.is_empty() => (m, t, v),
        _ => return Err(invalid(format!("malformed request line: {request_line:?}"))),
    };

    Ok(RequestHead {
        method: method.to_string(),
        target: target.to_string(),
        version: parse_version(version)?,
        headers: parse_header_lines(lines)?,
    })
}

/// Parse a complete response head.
pub fn parse_response_head(raw: &[u8]) -> io::Result<ResponseHead> {
    let text = std::str::from_utf8(raw).map_err(|_| invalid("head is not valid UTF-8"))?;
    let mut lines = text.lines();
    let status_line = lines.next().ok_or_else(|| invalid("empty response head"))?;

    // Status line: HTTP-version SP status-code SP [reason-phrase]
    let mut parts = status_line.splitn(3, ' ');
    let version = parse_version(parts.next().unwrap_or(""))?;
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .filter(|s| (100..=599).contains(s))
        .ok_or_else(|| invalid(format!("malformed status line: {status_line:?}")))?;
    let reason = parts.next().unwrap_or("").to_string();

    Ok(ResponseHead {
        version,
        status,
        reason,
        headers: parse_header_lines(lines)?,
    })
}

/// Case-insensitive header lookup (header names are case-insensitive per
/// RFC 9110; clients genuinely send `host`, `Host`, and `HOST`).
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Decide how a *request* body is framed, per RFC 9112 §6.
pub fn request_body_framing(head: &RequestHead) -> io::Result<BodyFraming> {
    let te = header(&head.headers, "transfer-encoding");
    let cl = header(&head.headers, "content-length");

    // A message with both Transfer-Encoding and Content-Length is the
    // canonical request-smuggling vector (proxy honors one, backend the
    // other). RFC 9112 says treat as an error at the edge; we reject.
    if te.is_some() && cl.is_some() {
        return Err(invalid("both Transfer-Encoding and Content-Length present"));
    }

    if let Some(te) = te {
        // "chunked" must be the final (and for us, only) coding.
        if te.eq_ignore_ascii_case("chunked") {
            return Ok(BodyFraming::Chunked);
        }
        return Err(invalid(format!("unsupported Transfer-Encoding: {te:?}")));
    }

    if let Some(cl) = cl {
        let n: u64 = cl
            .parse()
            .map_err(|_| invalid(format!("invalid Content-Length: {cl:?}")))?;
        return Ok(if n == 0 { BodyFraming::None } else { BodyFraming::Length(n) });
    }

    // No length information in a request means no body. (Requests cannot
    // use until-close framing.)
    Ok(BodyFraming::None)
}

/// Decide how a *response* body is framed. Needs the request method and the
/// status code because some responses are bodiless by definition.
pub fn response_body_framing(req_method: &str, head: &ResponseHead) -> io::Result<BodyFraming> {
    // HEAD responses and 1xx/204/304 carry no body regardless of headers.
    if req_method.eq_ignore_ascii_case("HEAD")
        || head.status / 100 == 1
        || head.status == 204
        || head.status == 304
    {
        return Ok(BodyFraming::None);
    }

    let te = header(&head.headers, "transfer-encoding");
    let cl = header(&head.headers, "content-length");

    if let Some(te) = te {
        if te.eq_ignore_ascii_case("chunked") {
            return Ok(BodyFraming::Chunked);
        }
        return Err(invalid(format!("unsupported Transfer-Encoding: {te:?}")));
    }

    if let Some(cl) = cl {
        let n: u64 = cl
            .parse()
            .map_err(|_| invalid(format!("invalid Content-Length: {cl:?}")))?;
        return Ok(if n == 0 { BodyFraming::None } else { BodyFraming::Length(n) });
    }

    // A response with no framing info is legal HTTP/1.0 style: the body is
    // "everything until the server closes the connection".
    Ok(BodyFraming::UntilClose)
}

/// Does the client want the connection kept open after this exchange?
/// HTTP/1.1 defaults to persistent; HTTP/1.0 defaults to close.
pub fn wants_keep_alive(version: Version, headers: &[(String, String)]) -> bool {
    match header(headers, "connection") {
        Some(v) if v.eq_ignore_ascii_case("close") => false,
        Some(v) if v.eq_ignore_ascii_case("keep-alive") => true,
        _ => version == Version::Http11,
    }
}

/// Serialize a request head for the backend leg.
pub fn write_request_head(head: &RequestHead) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(head.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(head.target.as_bytes());
    out.push(b' ');
    out.extend_from_slice(head.version.as_str().as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in &head.headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Serialize a response head for the client leg.
pub fn write_response_head(head: &ResponseHead) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(head.version.as_str().as_bytes());
    out.extend_from_slice(format!(" {} {}\r\n", head.status, head.reason).as_bytes());
    for (name, value) in &head.headers {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_head_end() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\nBODY"), Some(18));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\nHost: x"), None);
    }

    #[test]
    fn parses_request_head() {
        let raw = b"POST /api?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n";
        let head = parse_request_head(raw).unwrap();
        assert_eq!(head.method, "POST");
        assert_eq!(head.target, "/api?x=1");
        assert_eq!(head.version, Version::Http11);
        assert_eq!(header(&head.headers, "HOST"), Some("example.com"));
        assert_eq!(request_body_framing(&head).unwrap(), BodyFraming::Length(5));
    }

    #[test]
    fn rejects_malformed_request_line() {
        assert!(parse_request_head(b"GET /\r\n\r\n").is_err());
        assert!(parse_request_head(b"GET / HTTP/2.0\r\n\r\n").is_err());
        assert!(parse_request_head(b"\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_space_before_colon() {
        let raw = b"GET / HTTP/1.1\r\nHost : evil\r\n\r\n";
        assert!(parse_request_head(raw).is_err());
    }

    #[test]
    fn rejects_cl_plus_te() {
        let raw =
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        let head = parse_request_head(raw).unwrap();
        assert!(request_body_framing(&head).is_err());
    }

    #[test]
    fn chunked_request_framing() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let head = parse_request_head(raw).unwrap();
        assert_eq!(request_body_framing(&head).unwrap(), BodyFraming::Chunked);
    }

    #[test]
    fn parses_response_head() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\n";
        let head = parse_response_head(raw).unwrap();
        assert_eq!(head.status, 404);
        assert_eq!(head.reason, "Not Found");
        assert_eq!(
            response_body_framing("GET", &head).unwrap(),
            BodyFraming::Length(9)
        );
    }

    #[test]
    fn head_and_204_have_no_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        let head = parse_response_head(raw).unwrap();
        assert_eq!(response_body_framing("HEAD", &head).unwrap(), BodyFraming::None);

        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let head = parse_response_head(raw).unwrap();
        assert_eq!(response_body_framing("GET", &head).unwrap(), BodyFraming::None);
    }

    #[test]
    fn response_without_length_is_until_close() {
        let raw = b"HTTP/1.1 200 OK\r\nServer: old\r\n\r\n";
        let head = parse_response_head(raw).unwrap();
        assert_eq!(
            response_body_framing("GET", &head).unwrap(),
            BodyFraming::UntilClose
        );
    }

    #[test]
    fn keep_alive_defaults() {
        let h11: Vec<(String, String)> = vec![];
        assert!(wants_keep_alive(Version::Http11, &h11));
        assert!(!wants_keep_alive(Version::Http10, &h11));
        let close = vec![("Connection".to_string(), "close".to_string())];
        assert!(!wants_keep_alive(Version::Http11, &close));
        let ka = vec![("Connection".to_string(), "keep-alive".to_string())];
        assert!(wants_keep_alive(Version::Http10, &ka));
    }
}
