use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, Response, StatusCode},
    middleware::Next,
    response::IntoResponse,
};
use flate2::{
    write::{DeflateEncoder, GzEncoder},
    Compression,
};
use std::io::Write;
use tokio::task::spawn_blocking;

/// Supported content encodings
#[derive(Debug, Clone, Copy)]
pub enum ContentEncoding {
    /// The `gzip` encoding.
    Gzip,
    /// The `deflate` encoding.
    Deflate,
    /// No encoding.
    Identity,
}

impl ContentEncoding {
    /// Get the header value for this encoding
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Identity => "identity",
        }
    }
}

/// Middleware that compresses response bodies
pub async fn compression_middleware(request: Request, next: Next) -> axum::response::Response {
    // Don't compress streaming responses
    if request.headers().get(header::TRANSFER_ENCODING).is_some() {
        return next.run(request).await;
    }

    // Determine the best encoding
    let accept_encoding = request
        .headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let encoding = if accept_encoding.contains("gzip") {
        ContentEncoding::Gzip
    } else if accept_encoding.contains("deflate") {
        ContentEncoding::Deflate
    } else {
        ContentEncoding::Identity
    };

    // Don't compress if the client doesn't support compression or if the response is already compressed
    if matches!(encoding, ContentEncoding::Identity)
        || request.headers().get(header::CONTENT_ENCODING).is_some()
    {
        return next.run(request).await;
    }

    let response = next.run(request).await;
    let (mut parts, body) = response.into_parts();
    let bytes = match http_body_util::BodyExt::collect(body)
        .await
        .map(|c| c.to_bytes())
    {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::error!(error = %err, "Failed to read response body");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read response body",
            )
                .into_response();
        }
    };

    // Don't compress small responses
    if bytes.len() < 1024 {
        return Response::from_parts(parts, Body::from(bytes));
    }

    // Compress the body in a blocking task
    let compressed = match spawn_blocking(move || match encoding {
        ContentEncoding::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&bytes)?;
            encoder.finish()
        }
        ContentEncoding::Deflate => {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(&bytes)?;
            encoder.finish()
        }
        ContentEncoding::Identity => unreachable!(),
    })
    .await
    {
        Ok(Ok(compressed)) => compressed,
        Ok(Err(err)) => {
            tracing::error!(error = %err, "Failed to compress response body");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to compress response body",
            )
                .into_response();
        }
        Err(err) => {
            tracing::error!(error = %err, "Compression task failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to compress response body",
            )
                .into_response();
        }
    };

    // Set the content encoding header
    parts
        .headers
        .insert(header::CONTENT_ENCODING, HeaderValue::from_static("gzip"));

    // Update the content length
    parts.headers.remove(header::CONTENT_LENGTH);
    parts
        .headers
        .insert(header::CONTENT_LENGTH, HeaderValue::from(compressed.len()));

    Response::from_parts(parts, Body::from(compressed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::Request,
        http::StatusCode,
        routing::{get, Router},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_gzip_compression() {
        let app = Router::new()
            .route("/", get(|| async { "Hello, world!" }))
            .layer(
                tower::ServiceBuilder::new()
                    .layer(axum::middleware::from_fn(compression_middleware)),
            );

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header("accept-encoding", "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        if response.status() == StatusCode::OK {
            assert_eq!(
                response
                    .headers()
                    .get(header::CONTENT_ENCODING)
                    .and_then(|h| h.to_str().ok()),
                Some("gzip")
            );
        }
    }
}
