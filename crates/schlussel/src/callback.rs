use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use url::form_urlencoded;
use url::Url;

use crate::error::{Result, SchlusselError};

const SUCCESS_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>Authorization Successful</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
        .container { text-align: center; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #22c55e; margin-bottom: 16px; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authorization Successful</h1>
        <p>You can close this window and return to the application.</p>
    </div>
</body>
</html>
"#;

const ERROR_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>Authorization Failed</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background: #f5f5f5; }
        .container { text-align: center; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #ef4444; margin-bottom: 16px; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Authorization Failed</h1>
        <p>An error occurred during authorization. Please try again.</p>
    </div>
</body>
</html>
"#;

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CallbackResult {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

impl CallbackResult {
    pub fn is_success(&self) -> bool {
        self.code.is_some() && self.error_code.is_none()
    }
}

#[derive(Debug)]
pub struct CallbackServer {
    listener: TcpListener,
    port: u16,
}

impl CallbackServer {
    pub fn new(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .map_err(|error| SchlusselError::callback_server(error.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| SchlusselError::callback_server(error.to_string()))?;

        let port = listener
            .local_addr()
            .map_err(|error| SchlusselError::callback_server(error.to_string()))?
            .port();

        Ok(Self { listener, port })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn callback_url(&self) -> String {
        format!("http://127.0.0.1:{}/callback", self.port)
    }

    pub fn wait_for_callback(&self, timeout_seconds: u32) -> Result<CallbackResult> {
        let deadline = if timeout_seconds == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(u64::from(timeout_seconds)))
        };

        loop {
            match self.listener.accept() {
                Ok((mut stream, _)) => return handle_connection(&mut stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        return Err(SchlusselError::Timeout);
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                Err(error) => {
                    return Err(SchlusselError::callback_server(error.to_string()));
                }
            }
        }
    }
}

pub fn build_authorization_url(
    endpoint: &str,
    client_id: &str,
    redirect_uri: &str,
    scope: Option<&str>,
    state: &str,
    challenge: &str,
) -> Result<String> {
    let mut url = Url::parse(endpoint)?;
    {
        let mut pairs = url.query_pairs_mut();
        pairs.append_pair("response_type", "code");
        pairs.append_pair("client_id", client_id);
        pairs.append_pair("redirect_uri", redirect_uri);
        pairs.append_pair("state", state);
        pairs.append_pair("code_challenge", challenge);
        pairs.append_pair("code_challenge_method", "S256");
        if let Some(scope) = scope.filter(|scope| !scope.is_empty()) {
            pairs.append_pair("scope", scope);
        }
    }
    Ok(url.into())
}

pub fn open_browser(target: &str) -> Result<()> {
    webbrowser::open(target)
        .map(|_| ())
        .map_err(|error| SchlusselError::callback_server(error.to_string()))
}

fn handle_connection(stream: &mut TcpStream) -> Result<CallbackResult> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| SchlusselError::callback_server(error.to_string()))?;

    let mut buffer = [0_u8; 8192];
    let bytes_read = stream
        .read(&mut buffer)
        .map_err(|error| SchlusselError::callback_server(error.to_string()))?;
    if bytes_read == 0 {
        return Err(SchlusselError::callback_server(
            "callback connection closed before request".to_string(),
        ));
    }

    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let path = parse_path(&request)?;
    let result = parse_query(&path);

    let body = if result.is_success() {
        SUCCESS_HTML
    } else {
        ERROR_HTML
    };
    let status = if result.is_success() {
        "200 OK"
    } else {
        "400 Bad Request"
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .map_err(|error| SchlusselError::callback_server(error.to_string()))?;

    Ok(result)
}

fn parse_path(request: &str) -> Result<String> {
    let first_line = request
        .lines()
        .next()
        .ok_or_else(|| SchlusselError::callback_server("missing HTTP request line".to_string()))?;
    let mut parts = first_line.split_whitespace();
    let _method = parts.next();
    let path = parts
        .next()
        .ok_or_else(|| SchlusselError::callback_server("missing callback path".to_string()))?;
    Ok(path.to_string())
}

fn parse_query(path: &str) -> CallbackResult {
    let mut result = CallbackResult::default();
    if let Some((_, query)) = path.split_once('?') {
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "code" => result.code = Some(value.into_owned()),
                "state" => result.state = Some(value.into_owned()),
                "error" => result.error_code = Some(value.into_owned()),
                "error_description" => result.error_description = Some(value.into_owned()),
                _ => {}
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_authorization_url() {
        let url = build_authorization_url(
            "https://example.com/authorize",
            "client-id",
            "http://127.0.0.1/callback",
            Some("read write"),
            "state",
            "challenge",
        )
        .expect("url");

        assert!(url.contains("client_id=client-id"));
        assert!(url.contains("code_challenge=challenge"));
    }

    #[test]
    fn parses_callback_query() {
        let result = parse_query("/callback?code=abc123&state=xyz");
        assert_eq!(result.code.as_deref(), Some("abc123"));
        assert_eq!(result.state.as_deref(), Some("xyz"));
        assert!(result.is_success());
    }
}
