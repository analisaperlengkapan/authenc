//! Router construction and the middleware stack.

use std::{iter::once, time::Duration};

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderName, HeaderValue, Request, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use leptos::prelude::{LeptosOptions, provide_context};
use leptos_axum::{LeptosRoutes, generate_route_list, handle_server_fns_with_context};
use tower::ServiceBuilder;
use tower_http::{
    catch_panic::CatchPanicLayer,
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    sensitive_headers::SetSensitiveRequestHeadersLayer,
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{config::Config, health, state::AppState};

/// Header carrying the correlation id for a request.
const REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Build the application router.
pub fn router(state: AppState) -> Router {
    let config = state.config.clone();
    let leptos_options = state.leptos_options.clone();
    let routes = generate_route_list(authenc_web::App);

    let app = Router::new()
        // Probes come first and stay outside any auth: an orchestrator must be
        // able to reach them without credentials.
        .route("/health/live", get(health::live))
        .route("/health/ready", get(health::ready))
        // Server functions. `#[server(prefix = "/api/sfn")]` in authenc-web
        // must agree with this path.
        .route(
            "/api/sfn/{*path}",
            get(server_fn_handler).post(server_fn_handler),
        )
        // Leptos SSR routes, with application context injected so server
        // functions can reach the database.
        .leptos_routes_with_context(
            &state,
            routes,
            {
                let state = state.clone();
                move || provide_app_context(&state)
            },
            {
                let leptos_options = leptos_options.clone();
                move || authenc_web::shell(leptos_options.clone())
            },
        )
        .fallback(leptos_axum::file_and_error_handler::<AppState, _>(
            authenc_web::shell,
        ))
        .with_state(state);

    // The middleware stack, outermost first.
    //
    // `ServiceBuilder` applies layers in written order, so this reads the way
    // it executes. That matters: the previous server chained `.layer()` calls
    // with a comment claiming rate limiting ran "first (early rejection)", but
    // axum's `.layer()` makes the *last* call outermost — so rate limiting was
    // in fact the innermost layer, running only after the body had already
    // been read and validated.
    let stack = ServiceBuilder::new()
        // 1. Keep credentials out of the trace output.
        .layer(SetSensitiveRequestHeadersLayer::new(once(
            header::AUTHORIZATION,
        )))
        .layer(SetSensitiveRequestHeadersLayer::new(once(header::COOKIE)))
        // 2. Correlation id, so a log line can be tied to a request.
        .layer(SetRequestIdLayer::new(REQUEST_ID, MakeRequestUuid))
        .layer(PropagateRequestIdLayer::new(REQUEST_ID))
        // 3. Tracing, outside the handler so panics and timeouts are recorded.
        .layer(TraceLayer::new_for_http())
        // 4. Turn a panic into a 500 instead of a dead connection. Paired with
        //    `panic = "unwind"` in the release profile; with `abort` (as this
        //    project shipped) one panic in one request killed the process.
        .layer(CatchPanicLayer::new())
        // 5. Bound how long a request may occupy a worker.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::GATEWAY_TIMEOUT,
            config.server.request_timeout,
        ))
        // 6. Bound how much we will read before deciding anything.
        .layer(RequestBodyLimitLayer::new(config.server.max_body_bytes))
        // 7. Cross-origin policy, from configuration.
        .layer(cors(&config))
        // 8. Security headers.
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_FRAME_OPTIONS,
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("cross-origin-opener-policy"),
            HeaderValue::from_static("same-origin"),
        ))
        .option_layer(config.security.hsts.then(|| {
            SetResponseHeaderLayer::overriding(
                header::STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            )
        }))
        // 9. Compression last, so it wraps the finished body.
        .layer(CompressionLayer::new());

    app.layer(stack)
}

/// Cross-origin policy built from configuration.
///
/// An empty allow-list means same-origin only, which is the right default for
/// an admin console. It is never `Any`.
fn cors(config: &Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .security
        .cors_allowed_origins
        .iter()
        .filter_map(|origin| match HeaderValue::from_str(origin) {
            Ok(value) => Some(value),
            Err(_) => {
                tracing::warn!(%origin, "ignoring unparseable CORS origin");
                None
            }
        })
        .collect();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_credentials(true)
        .allow_headers([header::CONTENT_TYPE, header::ACCEPT])
        .max_age(Duration::from_secs(600))
}

/// Dispatch a server-function call with application context available.
async fn server_fn_handler(State(state): State<AppState>, request: Request<Body>) -> Response {
    handle_server_fns_with_context(move || provide_app_context(&state), request)
        .await
        .into_response()
}

/// Make application state reachable from server functions.
///
/// Server functions cannot take an `axum::extract::State`, so anything they
/// need is placed in the Leptos context — here, in exactly one place, so a
/// function cannot silently depend on something one router forgot to provide.
fn provide_app_context(state: &AppState) {
    provide_context(state.db.clone());
    provide_context(state.hasher.clone());
    provide_context(state.mailer.clone());
    provide_context(crate::auth::cookie_policy(&state.config));
    provide_context(crate::state::public_urls(&state.config));
}

/// Bind address derived from configuration.
#[must_use]
pub fn bind_address(config: &Config) -> std::net::SocketAddr {
    std::net::SocketAddr::new(config.server.host, config.server.port)
}

/// Resolve `LeptosOptions` from `cargo-leptos`' generated configuration.
///
/// # Errors
///
/// Returns an error if the configuration cannot be read.
pub fn leptos_options() -> Result<LeptosOptions, Box<dyn std::error::Error + Send + Sync>> {
    Ok(leptos::prelude::get_configuration(None)?.leptos_options)
}
