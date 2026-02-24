use gloo_net::http::{Request, Response};
use gloo_utils::window;
use serde::Serialize;
use web_sys::Storage;

pub async fn authenticated_request(
    method: &str,
    url: &str,
    body: Option<&impl Serialize>,
) -> Result<Response, String> {
    let token = window()
        .local_storage()
        .ok()
        .flatten()
        .and_then(|s: Storage| s.get_item("authenc_admin_token").ok())
        .flatten()
        .unwrap_or_default();

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

    let result = if let Some(body_data) = body {
        req.json(body_data).map_err(|e| e.to_string())?.send().await
    } else {
        req.send().await
    };

    result.map_err(|e| e.to_string())
}
