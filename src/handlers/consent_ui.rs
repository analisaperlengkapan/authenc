use axum::{
    Router,
    extract::{Extension, Form, Query, State},
    response::{Html, IntoResponse, Redirect},
    routing::{delete, get},
};

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AuthencError;
use crate::middleware::auth::AuthUser;
use crate::models::events::{Event, EventType};
use crate::services::stores::consent_store::ConsentStoreTrait;

/// Query parameters for consent page
#[derive(Debug, Deserialize, Serialize)]
pub struct ConsentQuery {
    /// OAuth2 client ID
    pub client_id: String,
    /// Requested scopes
    pub scope: Option<String>,
    /// Response type
    pub response_type: Option<String>,
    /// Redirect URI
    pub redirect_uri: Option<String>,
    /// State parameter
    pub state: Option<String>,
    /// PKCE code challenge
    pub code_challenge: Option<String>,
    /// PKCE code challenge method
    pub code_challenge_method: Option<String>,
    /// Nonce for OIDC
    pub nonce: Option<String>,
}

/// Form data for consent decision
#[derive(Debug, Deserialize, Serialize)]
pub struct ConsentDecision {
    /// Decision: "allow" or "deny"
    pub decision: String,
    /// Client ID (hidden field)
    pub client_id: String,
    /// Scopes (hidden field)
    pub scopes: String,
    /// Original OAuth2 parameters (JSON)
    pub oauth_params: String,
}

/// Test consent page handler - for testing without authentication
pub async fn test_consent_page(
    Query(params): Query<ConsentQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<axum::response::Response, AuthencError> {
    // Create a mock authenticated user for testing
    let auth_user = AuthUser {
        id: "550e8400-e29b-41d4-a716-446655440001".to_string(), // Test user ID
        email: "test@example.com".to_string(),
        roles: vec!["user".to_string()],
        session_id: None,
    };

    // Validate client
    let client = state
        .oidc_client_store
        .get(&params.client_id)
        .await?
        .ok_or_else(|| AuthencError::validation("Invalid client_id"))?;

    // Parse scopes
    let scopes: Vec<String> = params
        .scope
        .as_ref()
        .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
        .unwrap_or_default();

    // Get user ID
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID"))?;

    // Check if user already has consent
    let has_consent = state
        .consent_store
        .has_consent(user_id, &params.client_id, &scopes)
        .await?;

    if has_consent {
        // User already consented, redirect back to authorization
        return Ok(redirect_to_authorize(params)?.into_response());
    }

    // Generate HTML for consent page
    let html = generate_consent_html(&client, &scopes, &params, &auth_user);

    Ok(Html(html).into_response())
}

/// Consent page handler - shows consent form to user
pub async fn consent_page(
    Query(params): Query<ConsentQuery>,
    Extension(auth_user): Extension<AuthUser>,
    State(state): State<Arc<AppState>>,
) -> Result<axum::response::Response, AuthencError> {
    // Validate client
    let client = state
        .oidc_client_store
        .get(&params.client_id)
        .await?
        .ok_or_else(|| AuthencError::validation("Invalid client_id"))?;

    // Parse scopes
    let scopes: Vec<String> = params
        .scope
        .as_ref()
        .map(|s| s.split_whitespace().map(|s| s.to_string()).collect())
        .unwrap_or_default();

    // Get user ID
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID"))?;

    // Check if user already has consent
    let has_consent = state
        .consent_store
        .has_consent(user_id, &params.client_id, &scopes)
        .await?;

    if has_consent {
        // User already consented, redirect back to authorization
        return Ok(redirect_to_authorize(params)?.into_response());
    }

    // Generate HTML for consent page
    let html = generate_consent_html(&client, &scopes, &params, &auth_user);

    Ok(Html(html).into_response())
}

/// Process consent decision
pub async fn process_consent(
    Extension(auth_user): Extension<AuthUser>,
    State(state): State<Arc<AppState>>,
    Form(decision): Form<ConsentDecision>,
) -> Result<Redirect, AuthencError> {
    // Get user ID
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID"))?;

    match decision.decision.as_str() {
        "allow" => {
            // Parse scopes
            let scopes: Vec<String> = decision
                .scopes
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();

            // Grant consent
            let consent_request = crate::models::ConsentGrantRequest {
                client_id: decision.client_id.clone(),
                scopes: scopes.clone(),
                expires_in: Some(3600 * 24 * 365), // 1 year
                metadata: Some(serde_json::json!({
                    "granted_via": "consent_page",
                    "user_email": auth_user.email
                })),
            };

            let consent = state
                .consent_store
                .grant_consent(user_id, consent_request)
                .await?;

            // Log consent grant event
            let mut event = Event::new(EventType::GrantConsent, "master".to_string());
            event.user_id = Some(auth_user.id.clone());
            event.client_id = Some(decision.client_id.clone());
            event
                .details
                .insert("consent_id".to_string(), consent.id.to_string());
            event.details.insert("scopes".to_string(), scopes.join(" "));
            event.details.insert(
                "expires_at".to_string(),
                consent
                    .expires_at
                    .map_or("never".to_string(), |dt| dt.to_rfc3339()),
            );

            let event_manager = state.event_manager.read().await;
            if let Err(e) = event_manager.fire_event(event).await {
                tracing::error!("Failed to log consent grant event: {}", e);
            }

            // Parse OAuth params and redirect to authorization
            let oauth_params: ConsentQuery = serde_json::from_str(&decision.oauth_params)
                .map_err(|_| AuthencError::validation("Invalid OAuth parameters"))?;

            redirect_to_authorize(oauth_params)
        }
        "deny" => {
            // Log consent denial event
            let mut event = Event::new(EventType::RevokeGrant, "master".to_string());
            event.user_id = Some(auth_user.id.clone());
            event.client_id = Some(decision.client_id.clone());
            event
                .details
                .insert("action".to_string(), "consent_denied".to_string());
            event
                .details
                .insert("scopes".to_string(), decision.scopes.clone());

            let event_manager = state.event_manager.read().await;
            if let Err(e) = event_manager.fire_event(event).await {
                tracing::error!("Failed to log consent denial event: {}", e);
            }

            // User denied consent, redirect with error
            let oauth_params: ConsentQuery = serde_json::from_str(&decision.oauth_params)
                .map_err(|_| AuthencError::validation("Invalid OAuth parameters"))?;

            if let Some(redirect_uri) = oauth_params.redirect_uri {
                let error_url = format!(
                    "{}?error=access_denied&state={}",
                    redirect_uri,
                    oauth_params.state.unwrap_or_default()
                );
                Ok(Redirect::to(&error_url))
            } else {
                Err(AuthencError::validation("No redirect URI provided"))
            }
        }
        _ => Err(AuthencError::validation("Invalid consent decision")),
    }
}

/// Test consent decision handler - for testing without authentication
pub async fn test_process_consent(
    State(state): State<Arc<AppState>>,
    Form(decision): Form<ConsentDecision>,
) -> Result<Redirect, AuthencError> {
    // Create a mock authenticated user for testing
    let auth_user = AuthUser {
        id: "550e8400-e29b-41d4-a716-446655440001".to_string(), // Test user ID
        email: "test@example.com".to_string(),
        roles: vec!["user".to_string()],
        session_id: None,
    };

    // Get user ID
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID"))?;

    match decision.decision.as_str() {
        "allow" => {
            // Parse scopes
            let scopes: Vec<String> = decision
                .scopes
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();

            // Grant consent
            let consent_request = crate::models::ConsentGrantRequest {
                client_id: decision.client_id.clone(),
                scopes: scopes.clone(),
                expires_in: Some(3600 * 24 * 365), // 1 year
                metadata: Some(serde_json::json!({
                    "granted_via": "test_consent_page",
                    "user_email": auth_user.email
                })),
            };

            let consent = state
                .consent_store
                .grant_consent(user_id, consent_request)
                .await?;

            // Log consent grant event
            let mut event = Event::new(EventType::GrantConsent, "master".to_string());
            event.user_id = Some(auth_user.id.clone());
            event.client_id = Some(decision.client_id.clone());
            event
                .details
                .insert("consent_id".to_string(), consent.id.to_string());
            event.details.insert("scopes".to_string(), scopes.join(" "));
            event.details.insert(
                "expires_at".to_string(),
                consent
                    .expires_at
                    .map_or("never".to_string(), |dt| dt.to_rfc3339()),
            );
            event
                .details
                .insert("test_mode".to_string(), "true".to_string());

            let event_manager = state.event_manager.read().await;
            if let Err(e) = event_manager.fire_event(event).await {
                tracing::error!("Failed to log test consent grant event: {}", e);
            }

            // Parse OAuth params and redirect to authorization
            let oauth_params: ConsentQuery = serde_json::from_str(&decision.oauth_params)
                .map_err(|_| AuthencError::validation("Invalid OAuth parameters"))?;

            redirect_to_authorize(oauth_params)
        }
        "deny" => {
            // Log consent denial event
            let mut event = Event::new(EventType::RevokeGrant, "master".to_string());
            event.user_id = Some(auth_user.id.clone());
            event.client_id = Some(decision.client_id.clone());
            event
                .details
                .insert("action".to_string(), "consent_denied".to_string());
            event
                .details
                .insert("scopes".to_string(), decision.scopes.clone());
            event
                .details
                .insert("test_mode".to_string(), "true".to_string());

            let event_manager = state.event_manager.read().await;
            if let Err(e) = event_manager.fire_event(event).await {
                tracing::error!("Failed to log test consent denial event: {}", e);
            }

            // User denied consent, redirect with error
            let oauth_params: ConsentQuery = serde_json::from_str(&decision.oauth_params)
                .map_err(|_| AuthencError::validation("Invalid OAuth parameters"))?;

            if let Some(redirect_uri) = oauth_params.redirect_uri {
                let error_url = format!(
                    "{}?error=access_denied&state={}",
                    redirect_uri,
                    oauth_params.state.unwrap_or_default()
                );
                Ok(Redirect::to(&error_url))
            } else {
                Err(AuthencError::validation("No redirect URI provided"))
            }
        }
        _ => Err(AuthencError::validation("Invalid consent decision")),
    }
}

/// Generate HTML for consent page
fn generate_consent_html(
    client: &crate::models::oidc_client::OidcClient,
    scopes: &[String],
    params: &ConsentQuery,
    user: &AuthUser,
) -> String {
    let scopes_list = scopes
        .iter()
        .map(|scope| format!("<li>{}</li>", scope))
        .collect::<Vec<_>>()
        .join("");

    let oauth_params_json = serde_json::to_string(params).unwrap_or_default();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Consent Required - Authenc</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .consent-container {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 500px;
            width: 90%;
        }}
        .client-info {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .client-name {{
            font-size: 24px;
            font-weight: bold;
            color: #333;
            margin-bottom: 8px;
        }}
        .client-description {{
            color: #666;
            font-size: 16px;
        }}
        .user-info {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .user-email {{
            font-weight: bold;
            color: #333;
        }}
        .permissions {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }}
        .permissions h3 {{
            margin-top: 0;
            color: #333;
        }}
        .permissions ul {{
            margin: 0;
            padding-left: 20px;
        }}
        .permissions li {{
            margin-bottom: 8px;
            color: #555;
        }}
        .buttons {{
            display: flex;
            gap: 15px;
            justify-content: center;
        }}
        .btn {{
            padding: 12px 30px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .btn-allow {{
            background: #28a745;
            color: white;
        }}
        .btn-allow:hover {{
            background: #218838;
        }}
        .btn-deny {{
            background: #dc3545;
            color: white;
        }}
        .btn-deny:hover {{
            background: #c82333;
        }}
    </style>
</head>
<body>
    <div class="consent-container">
        <div class="client-info">
            <div class="client-name">{client_name}</div>
            <div class="client-description">wants to access your account</div>
        </div>

        <div class="user-info">
            <div>Logged in as: <span class="user-email">{user_email}</span></div>
        </div>

        <div class="permissions">
            <h3>Permissions Requested</h3>
            <p>This application is requesting access to:</p>
            <ul>
                {scopes_list}
            </ul>
        </div>

        <form method="post" action="/oauth2/consent">
            <input type="hidden" name="decision" value="allow">
            <input type="hidden" name="client_id" value="{client_id}">
            <input type="hidden" name="scopes" value="{scopes}">
            <input type="hidden" name="oauth_params" value='{oauth_params_json}'>

            <div class="buttons">
                <button type="submit" class="btn btn-allow">Allow Access</button>
                <button type="button" class="btn btn-deny" onclick="denyConsent()">Deny</button>
            </div>
        </form>
    </div>

    <script>
        function denyConsent() {{
            const form = document.querySelector('form');
            form.decision.value = 'deny';
            form.submit();
        }}
    </script>
</body>
</html>"#,
        client_name = client.name.as_str(),
        user_email = user.email,
        scopes_list = scopes_list,
        client_id = params.client_id,
        scopes = params.scope.as_deref().unwrap_or(""),
        oauth_params_json = oauth_params_json
    )
}

/// Helper function to redirect back to authorization endpoint
fn redirect_to_authorize(params: ConsentQuery) -> Result<Redirect, AuthencError> {
    // Build authorization URL
    let mut url = "/oauth2/authorize".to_string();
    let query_params = vec![
        ("client_id", Some(params.client_id)),
        ("scope", params.scope),
        ("response_type", params.response_type),
        ("redirect_uri", params.redirect_uri),
        ("state", params.state),
        ("code_challenge", params.code_challenge),
        ("code_challenge_method", params.code_challenge_method),
        ("nonce", params.nonce),
    ];

    let mut first = true;
    for (key, value) in query_params
        .into_iter()
        .filter_map(|(k, v)| v.map(|value| (k, value)))
    {
        if first {
            url.push('?');
            first = false;
        } else {
            url.push('&');
        }
        url.push_str(key);
        url.push('=');
        url.push_str(&urlencoding::encode(&value));
    }

    Ok(Redirect::to(&url))
}

/// List user consents handler
pub async fn list_user_consents(
    Extension(auth_user): Extension<AuthUser>,
    State(state): State<Arc<AppState>>,
) -> Result<axum::response::Response, AuthencError> {
    use axum::response::Json;
    use serde_json::json;

    // Get user ID
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID"))?;

    // Get user consents
    let consents = state.consent_store.get_user_consents(user_id).await?;

    // Convert to JSON response
    let consent_list: Vec<serde_json::Value> = consents
        .into_iter()
        .map(|consent| {
            json!({
                "id": consent.id,
                "client_id": consent.client_id,
                "scopes": consent.scopes,
                "granted_at": consent.granted_at,
                "expires_at": consent.expires_at,
                "metadata": consent.metadata
            })
        })
        .collect();

    Ok(Json(consent_list).into_response())
}

/// Revoke consent handler
pub async fn revoke_consent(
    Extension(auth_user): Extension<AuthUser>,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(consent_id): axum::extract::Path<String>,
) -> Result<axum::response::Response, AuthencError> {
    use axum::response::Json;

    // Get user ID
    let user_id = Uuid::parse_str(&auth_user.id)
        .map_err(|_| AuthencError::unauthorized("Invalid user ID"))?;

    // Parse consent ID
    let consent_uuid =
        Uuid::parse_str(&consent_id).map_err(|_| AuthencError::validation("Invalid consent ID"))?;

    // Revoke the consent
    state
        .consent_store
        .revoke_consent_by_id(user_id, consent_uuid)
        .await?;

    // Log consent revocation event
    let mut event = Event::new(EventType::RevokeGrant, "master".to_string());
    event.user_id = Some(auth_user.id.clone());
    event
        .details
        .insert("consent_id".to_string(), consent_id.clone());
    event
        .details
        .insert("action".to_string(), "consent_revoked".to_string());

    let event_manager = state.event_manager.read().await;
    if let Err(e) = event_manager.fire_event(event).await {
        tracing::error!("Failed to log consent revocation event: {}", e);
    }

    Ok(Json(serde_json::json!({
        "message": "Consent revoked successfully",
        "consent_id": consent_id
    }))
    .into_response())
}

/// Create consent UI routes
pub fn create_consent_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/oauth2/consent", get(consent_page).post(process_consent))
        .route("/consents", get(list_user_consents))
        .route("/consents/{consent_id}", delete(revoke_consent))
}

/// Create test consent UI routes for development and testing
pub fn create_test_consent_routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/oauth2/consent/test",
        get(test_consent_page).post(test_process_consent),
    )
}
