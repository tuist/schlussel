use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Parser;
use serde::Serialize;
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};
use url::form_urlencoded;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    host: String,
    #[arg(long, default_value_t = 0)]
    port: u16,
    #[arg(long)]
    port_file: PathBuf,
    #[arg(long)]
    state_dir: PathBuf,
}

#[derive(Debug, Default)]
struct OAuthState {
    device_counter: usize,
    auth_counter: usize,
    refresh_counter: usize,
    device_codes: HashMap<String, DeviceCodeRecord>,
    auth_codes: HashMap<String, AuthorizationCodeRecord>,
}

#[derive(Debug, Clone)]
struct DeviceCodeRecord {
    user_code: String,
    scope: String,
    approved: bool,
    refresh_token: String,
}

#[derive(Debug, Clone)]
struct AuthorizationCodeRecord {
    refresh_token: String,
}

#[derive(Debug, Serialize)]
struct ServerStats {
    refreshes: usize,
}

impl OAuthState {
    fn issue_device_code(&mut self, scope: String) -> (String, String) {
        self.device_counter += 1;
        let index = self.device_counter;
        let device_code = format!("device-{index}");
        let user_code = format!("USER-{index}");
        let refresh_token = format!("refresh-device-{index}");
        self.device_codes.insert(
            device_code.clone(),
            DeviceCodeRecord {
                user_code: user_code.clone(),
                scope,
                approved: false,
                refresh_token,
            },
        );
        (device_code, user_code)
    }

    fn approve_device_code(&mut self, user_code: &str) -> bool {
        for record in self.device_codes.values_mut() {
            if record.user_code == user_code {
                record.approved = true;
                return true;
            }
        }
        false
    }

    fn exchange_device_code(&mut self, device_code: &str) -> (u16, serde_json::Value) {
        let Some(record) = self.device_codes.get(device_code) else {
            return error_response(400, "invalid_request", Some("unknown device code"));
        };
        if !record.approved {
            return (400, serde_json::json!({ "error": "authorization_pending" }));
        }
        (
            200,
            serde_json::json!({
                "access_token": format!("device-access-{device_code}"),
                "token_type": "Bearer",
                "refresh_token": record.refresh_token,
                "expires_in": 60,
                "scope": record.scope,
            }),
        )
    }

    fn issue_authorization_code(&mut self) -> String {
        self.auth_counter += 1;
        let index = self.auth_counter;
        let code = format!("code-{index}");
        let refresh_token = format!("refresh-auth-{index}");
        self.auth_codes
            .insert(code.clone(), AuthorizationCodeRecord { refresh_token });
        code
    }

    fn exchange_authorization_code(&self, code: &str) -> (u16, serde_json::Value) {
        let Some(record) = self.auth_codes.get(code) else {
            return error_response(400, "invalid_grant", Some("unknown authorization code"));
        };
        (
            200,
            serde_json::json!({
                "access_token": format!("auth-access-{code}"),
                "token_type": "Bearer",
                "refresh_token": record.refresh_token,
                "expires_in": 60,
                "scope": "read write",
            }),
        )
    }

    fn refresh(&mut self, refresh_token: &str) -> (u16, serde_json::Value) {
        self.refresh_counter += 1;
        (
            200,
            serde_json::json!({
                "access_token": format!("refreshed-{refresh_token}"),
                "token_type": "Bearer",
                "refresh_token": refresh_token,
                "expires_in": 3600,
                "scope": "read write",
            }),
        )
    }

    fn stats(&self) -> ServerStats {
        ServerStats {
            refreshes: self.refresh_counter,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    fs::create_dir_all(&args.state_dir)?;

    let server = Server::http((args.host.as_str(), args.port))?;
    let port = server
        .server_addr()
        .to_ip()
        .map(|address| address.port())
        .unwrap_or(args.port);
    fs::write(&args.port_file, port.to_string())?;

    let state = Arc::new(Mutex::new(OAuthState::default()));
    for request in server.incoming_requests() {
        handle_request(request, &state, port);
    }

    Ok(())
}

fn handle_request(request: Request, state: &Arc<Mutex<OAuthState>>, port: u16) {
    let mut request = request;
    let method = request.method().clone();
    let url = request.url().to_string();
    let (path, query) = split_url(&url);

    match (method, path.as_str()) {
        (Method::Get, "/authorize") => {
            let params = parse_query_string(query.as_deref().unwrap_or_default());
            let Some(redirect_uri) = params.get("redirect_uri") else {
                let _ = send_json(
                    request,
                    400,
                    &serde_json::json!({ "error": "missing redirect_uri" }),
                );
                return;
            };
            let Some(state_param) = params.get("state") else {
                let _ = send_json(
                    request,
                    400,
                    &serde_json::json!({ "error": "missing state" }),
                );
                return;
            };
            let code = state
                .lock()
                .expect("state lock poisoned")
                .issue_authorization_code();
            let location = format!("{redirect_uri}?code={code}&state={state_param}");
            let _ = request.respond(
                Response::empty(StatusCode(302)).with_header(header("Location", &location)),
            );
        }
        (Method::Get, "/verify") => {
            let _ = request.respond(
                Response::from_string("verification page")
                    .with_status_code(StatusCode(200))
                    .with_header(header("Content-Type", "text/plain; charset=utf-8")),
            );
        }
        (Method::Get, "/health") => {
            let _ = send_json(request, 200, &serde_json::json!({ "ok": true }));
        }
        (Method::Get, "/stats") => {
            let stats = state.lock().expect("state lock poisoned").stats();
            let _ = send_json(
                request,
                200,
                &serde_json::to_value(stats).expect("stats json"),
            );
        }
        (Method::Post, "/device/code") => {
            let form = parse_form(&mut request);
            let scope = form.get("scope").cloned().unwrap_or_default();
            let (device_code, user_code) = state
                .lock()
                .expect("state lock poisoned")
                .issue_device_code(scope);
            let verification_uri = format!("http://127.0.0.1:{port}/verify");
            let _ = send_json(
                request,
                200,
                &serde_json::json!({
                    "device_code": device_code,
                    "user_code": user_code,
                    "verification_uri": verification_uri,
                    "verification_uri_complete": format!("{verification_uri}?user_code={user_code}"),
                    "expires_in": 600,
                    "interval": 1,
                }),
            );
        }
        (Method::Post, "/approve-device") => {
            let form = parse_form(&mut request);
            let approved = state
                .lock()
                .expect("state lock poisoned")
                .approve_device_code(form.get("user_code").map_or("", String::as_str));
            let status = if approved { 200 } else { 404 };
            let _ = send_json(
                request,
                status,
                &serde_json::json!({ "approved": approved }),
            );
        }
        (Method::Post, "/token") => {
            let form = parse_form(&mut request);
            let grant_type = form.get("grant_type").map_or("", String::as_str);
            let (status, payload) = match grant_type {
                "urn:ietf:params:oauth:grant-type:device_code" => state
                    .lock()
                    .expect("state lock poisoned")
                    .exchange_device_code(form.get("device_code").map_or("", String::as_str)),
                "authorization_code" => state
                    .lock()
                    .expect("state lock poisoned")
                    .exchange_authorization_code(form.get("code").map_or("", String::as_str)),
                "refresh_token" => state
                    .lock()
                    .expect("state lock poisoned")
                    .refresh(form.get("refresh_token").map_or("", String::as_str)),
                _ => error_response(400, "unsupported_grant_type", Some(grant_type)),
            };
            let _ = send_json(request, status, &payload);
        }
        _ => {
            let _ = send_json(request, 404, &serde_json::json!({ "error": "not_found" }));
        }
    }
}

fn parse_form(request: &mut Request) -> HashMap<String, String> {
    let mut body = String::new();
    request
        .as_reader()
        .read_to_string(&mut body)
        .expect("request body");
    parse_query_string(&body)
}

fn parse_query_string(raw: &str) -> HashMap<String, String> {
    form_urlencoded::parse(raw.as_bytes())
        .into_owned()
        .collect::<HashMap<_, _>>()
}

fn split_url(url: &str) -> (String, Option<String>) {
    match url.split_once('?') {
        Some((path, query)) => (path.to_string(), Some(query.to_string())),
        None => (url.to_string(), None),
    }
}

fn send_json(request: Request, status: u16, payload: &serde_json::Value) -> std::io::Result<()> {
    let body = serde_json::to_string(payload).expect("json body");
    request.respond(
        Response::from_string(body)
            .with_status_code(StatusCode(status))
            .with_header(header("Content-Type", "application/json"))
            .with_header(header("Cache-Control", "no-store")),
    )
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name, value).expect("valid header")
}

fn error_response(status: u16, error: &str, description: Option<&str>) -> (u16, serde_json::Value) {
    let mut payload = serde_json::json!({ "error": error });
    if let Some(description) = description {
        payload["error_description"] = serde_json::Value::String(description.to_string());
    }
    (status, payload)
}
