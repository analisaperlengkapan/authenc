use crate::app::AppState;
use authenc_crypto::utils::crypto::{jwt, password};
use authenc_models::models::realm::Realm;
use authenc_services::services::stores::user_store::UserStoreTrait;
use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse, Redirect},
    http::StatusCode,
};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
/// Payload for admin login form submission
pub struct LoginPayload {
    /// Username credential
    pub username: String,
    /// Password credential
    pub password: String,
    /// Realm name (optional, defaults to "master")
    pub realm: Option<String>,
}

/// Renders the admin login page
pub async fn login_page() -> Html<String> {
    Html(r#"
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>Authenc Admin Login</title>
        <style>
            body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background-color: #f5f5f5; margin: 0; }
            .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 320px; }
            h2 { margin-top: 0; color: #2c3e50; text-align: center; margin-bottom: 24px; }
            .form-group { margin-bottom: 16px; }
            label { display: block; margin-bottom: 6px; color: #666; font-size: 14px; }
            input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; font-size: 16px; }
            input:focus { border-color: #007bff; outline: none; }
            button { width: 100%; padding: 12px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; font-weight: bold; margin-top: 10px; }
            button:hover { background: #0056b3; }
            .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 4px; margin-bottom: 16px; display: none; text-align: center; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>Admin Console</h2>
            <div id="error-msg" class="error">Invalid credentials</div>
            <form action="/admin/login" method="post">
                <div class="form-group">
                    <label for="realm">Realm</label>
                    <input type="text" id="realm" name="realm" value="master" required>
                </div>
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required autofocus>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Log In</button>
            </form>
        </div>
        <script>
            if (window.location.search.includes('error=invalid')) {
                document.getElementById('error-msg').style.display = 'block';
            }
        </script>
    </body>
    </html>
    "#.to_string())
}

/// Handles the login form submission
/// Verifies credentials and sets the `authenc_admin_token` cookie on success
pub async fn login_handler(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
    Form(payload): Form<LoginPayload>,
) -> impl IntoResponse {
    let realm_name = payload.realm.as_deref().unwrap_or("master");

    // Find realm
    let realm = match state.realm_store.get_by_name(realm_name) {
        Some(r) => r,
        None => return (jar, Redirect::to("/admin/login?error=invalid")),
    };

    // Find user
    let user_result = state.user_store.get_user_by_username(&realm.id, &payload.username).await;

    let user = match user_result {
        Ok(Some(u)) => u,
        _ => return (jar, Redirect::to("/admin/login?error=invalid")),
    };

    // Verify password
    if let Some(hash) = user.password_hash {
        let is_valid = match password::verify_password(&hash, &payload.password).await {
            Ok(v) => v,
            Err(_) => return (jar, Redirect::to("/admin/login?error=invalid")),
        };

        if !is_valid {
            return (jar, Redirect::to("/admin/login?error=invalid"));
        }
    } else {
        // User has no password set
        return (jar, Redirect::to("/admin/login?error=invalid"));
    }

    // Generate token
    // Using user.id.to_string() as subject
    // We should probably include roles, but for now simple subject is enough
    let token = match jwt::generate_jwt(&user.id.to_string()) {
        Ok(t) => t,
        Err(_) => return (jar, Redirect::to("/admin/login?error=invalid")),
    };

    // Set cookie
    // HttpOnly for security, Secure in production (but tricky here without checking config, assuming dev for now)
    let cookie = Cookie::build(("authenc_admin_token", token))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .build();

    (jar.add(cookie), Redirect::to("/admin/console/"))
}
