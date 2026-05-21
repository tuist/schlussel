use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};

use super::config::OAuthConfig;

#[derive(Debug)]
pub(crate) struct CapturedRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) body: String,
}

#[derive(Debug)]
pub(crate) struct OneShotServer {
    base_url: String,
    requests: Receiver<CapturedRequest>,
    handle: Option<JoinHandle<()>>,
}

impl OneShotServer {
    pub(crate) fn respond(
        status: u16,
        content_type: &'static str,
        body: impl Into<String>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("listener address");
        let response_body = body.into();
        let (request_tx, requests) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept request");
            let mut reader = BufReader::new(stream);

            let mut request_line = String::new();
            reader.read_line(&mut request_line).expect("request line");
            let mut content_length = 0usize;

            loop {
                let mut line = String::new();
                reader.read_line(&mut line).expect("header line");
                if line == "\r\n" || line.is_empty() {
                    break;
                }

                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().expect("content length");
                    }
                }
            }

            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).expect("request body");
            let request = parse_request(&request_line, body);
            request_tx.send(request).expect("send captured request");

            let response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );
            reader
                .get_mut()
                .write_all(response.as_bytes())
                .expect("write response");
        });

        Self {
            base_url: format!("http://{address}"),
            requests,
            handle: Some(handle),
        }
    }

    pub(crate) fn endpoint(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub(crate) fn next_request(&self) -> CapturedRequest {
        self.requests.recv().expect("captured request")
    }
}

impl Drop for OneShotServer {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

pub(crate) fn oauth_config(token_endpoint: impl Into<String>) -> OAuthConfig {
    OAuthConfig {
        client_id: "client-id".to_string(),
        client_secret: Some("secret".to_string()),
        authorization_endpoint: "https://example.com/authorize".to_string(),
        token_endpoint: token_endpoint.into(),
        redirect_uri: "http://127.0.0.1/callback".to_string(),
        scope: Some("repo user".to_string()),
        device_authorization_endpoint: None,
    }
}

fn parse_request(request_line: &str, body: Vec<u8>) -> CapturedRequest {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();

    CapturedRequest {
        method,
        path,
        body: String::from_utf8(body).expect("UTF-8 request body"),
    }
}
