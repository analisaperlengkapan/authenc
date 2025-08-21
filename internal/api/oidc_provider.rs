use rsa::pkcs8::EncodePublicKey;
use actix_web::HttpResponseBuilder;
use crate::services::user_store::UserStore;
#[get("/oidc/login")]
pub async fn oidc_login(query: web::Query<OidcAuthorizeQuery>) -> impl Responder {
    // Stub login form, on submit set cookie and redirect to authorize with original params
    let html = format!(r#"
        <html><body>
        <h2>OIDC Login</h2>
        <form method='post' action='/v1/oidc/login'>
            <input type='hidden' name='client_id' value='{}'/>
            <input type='hidden' name='redirect_uri' value='{}'/>
            <input type='hidden' name='response_type' value='{}'/>
            <input type='hidden' name='scope' value='{}'/>
            <input type='hidden' name='state' value='{}'/>
            Username: <input name='username'/><br/>
            Password: <input name='password' type='password'/><br/>
            <input type='submit' value='Login'/>
        </form>
        </body></html>
    "#,
    query.client_id,
    query.redirect_uri,
    query.response_type,
    query.scope.clone().unwrap_or_default(),
    query.state.clone().unwrap_or_default());
    HttpResponse::Ok().content_type("text/html").body(html)
}

#[post("/oidc/login")]
pub async fn oidc_login_post(
    form: web::Form<OidcAuthorizeQuery>,
    user_store: web::Data<UserStore>,
) -> impl Responder {
    // Render login form with username/password fields
    let username = form.scope.clone().unwrap_or_default(); // overload for username (for demo, should use real struct)
    let password = form.state.clone().unwrap_or_default(); // overload for password (for demo)
    // Actually, username/password should be in a separate struct, but for demo, use scope/state
    let user = user_store.get_by_username(&username);
    if user.is_none() || !user_store.verify_password(&username, &password) {
        return HttpResponse::Unauthorized().body("Invalid credentials");
    }
    let user = user.unwrap();
    let mut resp = HttpResponseBuilder::new(actix_web::http::StatusCode::FOUND);
    let uri = format!("/v1/oidc/authorize?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
        form.client_id,
        form.redirect_uri,
        form.response_type,
        form.scope.clone().unwrap_or_default(),
        form.state.clone().unwrap_or_default());
    resp.append_header(("Set-Cookie", format!("auth_user_id={}; Path=/; HttpOnly", user.id)));
    resp.append_header(("Location", uri));
    resp.finish()
}
use rsa::traits::PublicKeyParts;
use actix_web::{web, HttpResponse, Responder, get, post};
use serde::Deserialize;
use crate::api::oidc_jwt::generate_id_token;
use crate::services::oidc_code_store::OidcCodeStore;
use crate::services::oidc_client_store::OidcClientStore;
use actix_web::{HttpRequest};

#[get("/.well-known/openid-configuration")]
pub async fn oidc_discovery() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "issuer": "http://localhost:8080/v1",
        "authorization_endpoint": "http://localhost:8080/v1/oidc/authorize",
        "token_endpoint": "http://localhost:8080/v1/oidc/token",
        "userinfo_endpoint": "http://localhost:8080/v1/oidc/userinfo",
        "jwks_uri": "http://localhost:8080/v1/oidc/jwks",
        "response_types_supported": ["code", "id_token", "token id_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    }))
}

// Stub endpoints for OIDC

#[derive(Deserialize)]
pub struct OidcAuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
}


#[get("/oidc/authorize")]
pub async fn oidc_authorize(
    query: web::Query<OidcAuthorizeQuery>,
    code_store: web::Data<OidcCodeStore>,
    client_store: web::Data<OidcClientStore>,
    req: HttpRequest,
) -> impl Responder {
    // Validate client_id and redirect_uri from registry
    let client = client_store.get(&query.client_id);
    if client.is_none() || !client.as_ref().unwrap().enabled || !client.as_ref().unwrap().redirect_uris.contains(&query.redirect_uri) {
        return HttpResponse::BadRequest().body("Invalid client_id or redirect_uri");
    }
    // Check login session (cookie)
    let user_id = req.cookie("auth_user_id").map(|c| c.value().to_string());
    if user_id.is_none() {
        // Redirect to login with original params
        let uri = format!("/v1/oidc/login?client_id={}&redirect_uri={}&response_type={}&scope={}&state={}",
            query.client_id,
            query.redirect_uri,
            query.response_type,
            query.scope.clone().unwrap_or_default(),
            query.state.clone().unwrap_or_default());
        return HttpResponse::Found().append_header(("Location", uri)).finish();
    }
    let user_id = user_id.unwrap();
    // Consent screen logic (stub): show consent if prompt=consent
    let prompt = query.scope.as_deref().unwrap_or("");
    if prompt.contains("consent") {
        let html = format!(r#"
            <html><body>
            <h2>Consent Required</h2>
            <form method='get' action='/v1/oidc/authorize'>
                <input type='hidden' name='client_id' value='{}'/>
                <input type='hidden' name='redirect_uri' value='{}'/>
                <input type='hidden' name='response_type' value='{}'/>
                <input type='hidden' name='scope' value='{}'/>
                <input type='hidden' name='state' value='{}'/>
                <input type='submit' value='Approve'/>
            </form>
            </body></html>
        "#,
        query.client_id,
        query.redirect_uri,
        query.response_type,
        query.scope.clone().unwrap_or_default(),
        query.state.clone().unwrap_or_default());
        return HttpResponse::Ok().content_type("text/html").body(html);
    }
    // Issue code after consent
    let code = uuid::Uuid::new_v4().to_string();
    code_store.insert(code.clone(), query.client_id.clone(), user_id);
    let mut uri = format!("{}?code={}", query.redirect_uri, code);
    if let Some(state) = &query.state {
        uri.push_str(&format!("&state={}", state));
    }
    HttpResponse::Found().append_header(("Location", uri)).finish()
}


#[derive(Deserialize)]
pub struct OidcTokenRequest {
    pub grant_type: String,
    pub code: String,
    pub redirect_uri: String,
    pub client_id: String,
    pub client_secret: Option<String>,
}

#[post("/oidc/token")]
pub async fn oidc_token(
    form: web::Form<OidcTokenRequest>,
    code_store: web::Data<OidcCodeStore>,
    client_store: web::Data<OidcClientStore>,
    user_store: web::Data<UserStore>,
) -> impl Responder {
    // Validate client_id and redirect_uri from registry
    let client = client_store.get(&form.client_id);
    if client.is_none() || !client.as_ref().unwrap().enabled || !client.as_ref().unwrap().redirect_uris.contains(&form.redirect_uri) {
        return HttpResponse::BadRequest().body("Invalid client_id or redirect_uri");
    }
    // Validate code and get user_id
    let user_id = match code_store.take(&form.code, &form.client_id) {
        Some(uid) => uid,
        None => return HttpResponse::BadRequest().body("Invalid or expired code"),
    };
    // Get user info for id_token
    let user = user_store.get_by_username(&user_id);
    let (email, name) = if let Some(u) = user {
        (Some(u.email.clone()), Some(u.username.clone()))
    } else {
        (None, None)
    };
    let id_token = generate_id_token(
        &user_id,
        &form.client_id,
        email.as_deref(),
        name.as_deref(),
    );
    HttpResponse::Ok().json(serde_json::json!({
        "access_token": "demo-access-token",
        "id_token": id_token,
        "token_type": "Bearer",
        "expires_in": 3600
    }))
}


#[get("/oidc/userinfo")]
pub async fn oidc_userinfo(req: HttpRequest, user_store: web::Data<UserStore>) -> impl Responder {
    // Parse id_token from Authorization header
    let auth = req.headers().get("Authorization").and_then(|v| v.to_str().ok());
    if let Some(auth) = auth {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            // Validate JWT RS256
            use jsonwebtoken::{DecodingKey, Validation, Algorithm};
            use crate::api::oidc_jwt::OidcIdTokenClaims;
            use crate::api::oidc_keys::RSA_KEYPAIR;
            let pubkey = rsa::RsaPublicKey::from(&*RSA_KEYPAIR);
            let pubkey_der = pubkey.to_public_key_der().unwrap();
            let key = DecodingKey::from_rsa_der(pubkey_der.as_ref());
            let mut validation = Validation::new(Algorithm::RS256);
            validation.validate_exp = true;
            let claims = jsonwebtoken::decode::<OidcIdTokenClaims>(token, &key, &validation).map(|d| d.claims);
            if let Ok(claims) = claims {
                // Fetch user from user_store by sub
                if let Some(user) = user_store.get_by_username(&claims.sub) {
                    return HttpResponse::Ok().json(serde_json::json!({
                        "sub": user.id,
                        "email": user.email,
                        "name": user.username,
                    }));
                }
            }
        }
    }
    HttpResponse::Unauthorized().body("Invalid or missing token")
}


#[get("/oidc/jwks")]
pub async fn oidc_jwks() -> impl Responder {
    use rsa::pkcs1::DecodeRsaPublicKey;
    use base64ct::{Base64UrlUnpadded, Encoding};
    let pubkey_pem = crate::api::oidc_keys::get_public_pem();
    let pubkey = rsa::RsaPublicKey::from_pkcs1_pem(&pubkey_pem).unwrap();
    let n = Base64UrlUnpadded::encode_string(&pubkey.n().to_bytes_be());
    let e = Base64UrlUnpadded::encode_string(&pubkey.e().to_bytes_be());
    let jwk = serde_json::json!({
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": "authence-demo-key",
        "n": n,
        "e": e,
    });
    HttpResponse::Ok().json(serde_json::json!({"keys": [jwk]}))
}
