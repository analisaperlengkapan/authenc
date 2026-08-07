//! Sending mail.
//!
//! This is one of the two places the codebase uses a trait for substitution
//! rather than testing against the real thing (the other is an external
//! identity provider). The reason is narrow and specific: an SMTP server
//! cannot be part of an ordinary test run, and a test that quietly skipped
//! when one was absent would be exactly the pattern this rebuild removed.
//! [`CapturingMailer`] lets a test assert on what *would* have been sent.

use std::sync::{Arc, Mutex};

use authenc_contract::{AppError, Result};

/// One outbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// Recipient address.
    pub to: String,
    /// Subject line.
    pub subject: String,
    /// Plain-text body. No HTML: a password-reset mail has nothing to gain
    /// from it, and plain text cannot carry a tracking pixel or a mismatched
    /// link label.
    pub body: String,
}

/// Something that can send mail.
#[async_trait::async_trait]
pub trait Mailer: Send + Sync {
    /// Send one message.
    ///
    /// # Errors
    ///
    /// Returns an error if the message could not be handed to the transport.
    async fn send(&self, message: Message) -> Result<()>;
}

/// A mailer that logs instead of sending.
///
/// The default in development, so a fresh checkout produces a working reset
/// link in the log without any SMTP setup. It is refused under the production
/// profile — a reset flow that silently sends nothing is worse than one that
/// is switched off.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoggingMailer;

#[async_trait::async_trait]
impl Mailer for LoggingMailer {
    async fn send(&self, message: Message) -> Result<()> {
        tracing::info!(
            to = %message.to,
            subject = %message.subject,
            body = %message.body,
            "mail not sent: no SMTP transport configured",
        );
        Ok(())
    }
}

/// A mailer that keeps messages in memory, for tests.
#[derive(Debug, Clone, Default)]
pub struct CapturingMailer {
    sent: Arc<Mutex<Vec<Message>>>,
}

impl CapturingMailer {
    /// Create an empty capturing mailer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every message sent so far.
    ///
    /// Returns what was captured before the lock was poisoned, if it was: a
    /// test assertion should report the messages it can see rather than
    /// panicking a second time on top of whatever poisoned the lock.
    #[must_use]
    pub fn sent(&self) -> Vec<Message> {
        match self.sent.lock() {
            Ok(sent) => sent.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

#[async_trait::async_trait]
impl Mailer for CapturingMailer {
    async fn send(&self, message: Message) -> Result<()> {
        self.sent
            .lock()
            .map_err(|_| AppError::internal("capturing mailer lock poisoned"))?
            .push(message);
        Ok(())
    }
}

/// Sends over SMTP.
///
/// Built from a URL, so `smtp://localhost:1025` reaches MailHog in
/// development and `smtps://user:pass@host:465` reaches a real relay. The
/// transport is pooled and shared.
#[derive(Clone)]
pub struct SmtpMailer {
    transport: lettre::AsyncSmtpTransport<lettre::Tokio1Executor>,
    from: lettre::message::Mailbox,
}

impl std::fmt::Debug for SmtpMailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never derive this: the URL carries the relay password.
        f.debug_struct("SmtpMailer")
            .field("from", &self.from)
            .finish_non_exhaustive()
    }
}

impl SmtpMailer {
    /// Build a mailer from an SMTP URL and a `From` address.
    ///
    /// Must be called from within a Tokio runtime: the pooled transport
    /// registers with the reactor as it is built.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL or the address cannot be parsed. Doing this
    /// at construction means a typo in the relay address fails at startup
    /// rather than on the first password reset.
    pub fn new(url: &str, from: &str) -> Result<Self> {
        let transport = lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::from_url(url)
            .map_err(|e| AppError::internal_from("parsing the SMTP URL", e))?
            .build();

        let from = from
            .parse::<lettre::message::Mailbox>()
            .map_err(|e| AppError::internal_from("parsing the From address", e))?;

        Ok(Self { transport, from })
    }
}

#[async_trait::async_trait]
impl Mailer for SmtpMailer {
    async fn send(&self, message: Message) -> Result<()> {
        use lettre::AsyncTransport as _;

        let to = message
            .to
            .parse::<lettre::message::Mailbox>()
            .map_err(|e| AppError::internal_from("parsing the recipient address", e))?;

        let email = lettre::Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(message.subject)
            .header(lettre::message::header::ContentType::TEXT_PLAIN)
            .body(message.body)
            .map_err(|e| AppError::internal_from("building the message", e))?;

        self.transport
            .send(email)
            .await
            .map_err(|e| AppError::internal_from("sending mail", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_capturing_mailer_records_what_it_was_given() {
        let mailer = CapturingMailer::new();
        assert!(mailer.sent().is_empty());

        mailer
            .send(Message {
                to: "alice@example.com".into(),
                subject: "Reset your password".into(),
                body: "https://example.com/reset?token=abc".into(),
            })
            .await
            .unwrap();

        let sent = mailer.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "alice@example.com");
    }

    #[tokio::test]
    async fn the_smtp_mailer_never_reveals_its_url_in_debug_output() {
        let mailer = SmtpMailer::new(
            "smtp://relay:hunter2@mail.example.com:587",
            "Authenc <no-reply@example.com>",
        )
        .unwrap();

        let rendered = format!("{mailer:?}");
        assert!(!rendered.contains("hunter2"), "leaked: {rendered}");
    }

    #[tokio::test]
    async fn a_malformed_smtp_url_or_address_is_rejected_at_construction() {
        // Better to fail at startup than on the first password reset.
        assert!(SmtpMailer::new("not a url", "a@b.co").is_err());
        assert!(SmtpMailer::new("smtp://localhost:1025", "not an address").is_err());
    }

    #[tokio::test]
    async fn the_logging_mailer_succeeds_without_sending() {
        // It must not fail: development would otherwise be unusable. It must
        // also be impossible to select in production, which `Config::validate`
        // enforces.
        LoggingMailer
            .send(Message {
                to: "alice@example.com".into(),
                subject: "x".into(),
                body: "y".into(),
            })
            .await
            .unwrap();
    }
}
