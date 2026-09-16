//! Scopes: parsing, narrowing, and describing.
//!
//! A scope string is space-delimited (RFC 6749 §3.3) and order carries no
//! meaning, so everything here normalises to a deduplicated list. The one rule
//! that matters for security is in [`resolve`]: a request can only ever
//! *narrow* what a client is registered for, never widen it.

use crate::error::OAuthError;

/// The scope that turns an OAuth authorization into an OIDC one.
pub const OPENID: &str = "openid";
/// Profile claims: `preferred_username`, and the name fields.
pub const PROFILE: &str = "profile";
/// The user's email address and whether it has been verified.
pub const EMAIL: &str = "email";
/// Asks for a refresh token alongside the access token.
pub const OFFLINE_ACCESS: &str = "offline_access";

/// Every scope this server understands, in the order a consent screen should
/// list them.
pub const SUPPORTED: &[&str] = &[OPENID, PROFILE, EMAIL, OFFLINE_ACCESS];

/// Split a scope parameter into its parts, deduplicated, order preserved.
#[must_use]
pub fn parse(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in raw.split_whitespace() {
        if !out.iter().any(|seen| seen == part) {
            out.push(part.to_owned());
        }
    }
    out
}

/// Render a scope list back into a parameter value.
#[must_use]
pub fn join(scopes: &[String]) -> String {
    scopes.join(" ")
}

/// Narrow a request against what the client is registered for.
///
/// An empty request means "everything the client may have", which is what
/// RFC 6749 §3.3 allows a server to do when `scope` is omitted. A request that
/// names something the client is *not* registered for is refused rather than
/// silently trimmed: silently trimming leaves the client believing it holds
/// access it does not have, and the mismatch only surfaces later as a confusing
/// 403 from a resource server.
///
/// # Errors
///
/// Returns `invalid_scope` naming the first scope that is not permitted.
pub fn resolve(requested: &[String], registered: &[String]) -> Result<Vec<String>, OAuthError> {
    if requested.is_empty() {
        return Ok(registered.to_vec());
    }

    for scope in requested {
        if !registered.iter().any(|allowed| allowed == scope) {
            return Err(OAuthError::invalid_scope(format!(
                "the client is not registered for scope '{scope}'"
            )));
        }
    }

    Ok(requested.to_vec())
}

/// Whether a previously granted set already covers everything now requested.
///
/// Used to decide whether the user has to be asked again.
#[must_use]
pub fn covers(granted: &[String], requested: &[String]) -> bool {
    requested
        .iter()
        .all(|scope| granted.iter().any(|held| held == scope))
}

/// A one-line explanation of a scope, for the consent screen.
///
/// Unknown scopes get their own name back rather than a placeholder, so a
/// custom scope still shows the user something truthful.
#[must_use]
pub fn describe(scope: &str) -> &str {
    match scope {
        OPENID => "Confirm your identity",
        PROFILE => "See your username and name",
        EMAIL => "See your email address",
        OFFLINE_ACCESS => "Stay signed in when you are away",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn parsing_collapses_whitespace_and_duplicates() {
        assert_eq!(
            parse("  openid   profile openid  "),
            owned(&["openid", "profile"]),
        );
        assert!(parse("   ").is_empty());
    }

    #[test]
    fn a_request_can_only_narrow_what_the_client_is_registered_for() {
        let registered = owned(&["openid", "profile", "email"]);

        assert_eq!(
            resolve(&owned(&["openid"]), &registered).unwrap(),
            owned(&["openid"]),
        );

        let error = resolve(&owned(&["openid", "admin"]), &registered).unwrap_err();
        assert_eq!(error.code, crate::error::OAuthErrorCode::InvalidScope);
        assert!(error.description.contains("admin"), "{error}");
    }

    #[test]
    fn omitting_scope_means_everything_the_client_may_have() {
        let registered = owned(&["openid", "email"]);
        assert_eq!(resolve(&[], &registered).unwrap(), registered);
    }

    #[test]
    fn a_client_registered_for_nothing_gets_nothing() {
        assert!(resolve(&[], &[]).unwrap().is_empty());
        assert!(resolve(&owned(&["openid"]), &[]).is_err());
    }

    #[test]
    fn consent_is_only_reusable_when_it_covers_the_whole_request() {
        let granted = owned(&["openid", "profile"]);
        assert!(covers(&granted, &owned(&["openid"])));
        assert!(covers(&granted, &granted));
        assert!(!covers(&granted, &owned(&["openid", "email"])));
    }

    #[test]
    fn an_unknown_scope_is_described_by_its_own_name() {
        // Better than "Unknown permission": the user sees the actual string
        // they are being asked to grant.
        assert_eq!(describe("billing:read"), "billing:read");
        assert_eq!(describe(EMAIL), "See your email address");
    }
}
