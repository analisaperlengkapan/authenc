use gloo_net::http::{Request, Response};
use gloo_utils::window;
use serde::Serialize;
use web_sys::Storage;

fn get_cookie(name: &str) -> Option<String> {
    let document = window().document()?;
    let cookie_str = document.cookie().ok()?;

    for cookie in cookie_str.split(';') {
        let cookie = cookie.trim();
        if let Some(stripped) = cookie.strip_prefix(name) {
            if let Some(val) = stripped.strip_prefix('=') {
                return Some(val.to_string());
            }
        }
    }
    None
}

pub async fn authenticated_request(
    method: &str,
    url: &str,
    body: Option<&impl Serialize>,
) -> Result<Response, String> {
    let token = window()
        .local_storage()
        .ok()
        .flatten()
        .and_then(|s: Storage| s.get_item("authenc_token").ok())
        .flatten()
        .unwrap_or_default();

    // Extract CSRF token from cookie for state-changing requests
    let csrf_token = get_cookie("csrf_token");

    let mut req = match method {
        "GET" => Request::get(url),
        "POST" => Request::post(url),
        "PUT" => Request::put(url),
        "DELETE" => Request::delete(url),
        _ => return Err(format!("Unsupported method: {}", method)),
    };

    if !token.is_empty() {
        req = req.header("Authorization", &format!("Bearer {}", token));
    }

    if let Some(csrf) = csrf_token {
        req = req.header("X-CSRF-Token", &csrf);
    }

    let result = if let Some(body_data) = body {
        req.json(body_data).map_err(|e| e.to_string())?.send().await
    } else {
        req.send().await
    };

    result.map_err(|e| e.to_string())
}
