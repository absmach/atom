//! Renders and sends Atom's transactional emails (signup verification,
//! password reset, tenant invitation) from templates that can be overridden
//! at runtime, without rebuilding the image.
//!
//! Each template is a single `.tmpl` file shaped like a minimal RFC 5322
//! message: a `Subject: ...` header line, an optional `Content-Type: ...`
//! header line (defaults to `text/plain` when absent), a blank line, then
//! the body — all rendered with [minijinja](https://docs.rs/minijinja)
//! `{{ variable }}` placeholders. Every template ships a built-in default
//! under `DEFAULT_TEMPLATES_DIR` (baked into the container image alongside
//! the binary). Setting `cfg.email_templates_dir`
//! (`ATOM_EMAIL_TEMPLATES_DIR`) points at a separate directory — typically a
//! Compose bind mount — that is checked first, one file at a time, so an
//! operator only needs to provide the templates they actually want to
//! customize.

use std::path::{Path, PathBuf};

use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, AsyncSmtpTransport,
    AsyncTransport, Message, Tokio1Executor,
};

use crate::config::{Config, SmtpConfig, SmtpTls};
use crate::error::AppError;

/// Built-in template directory, relative to the process's working directory
/// (the crate root in `cargo run`/`cargo test`, `/app` — via the Dockerfile's
/// `WORKDIR` and `COPY email-templates ./email-templates` — in the image).
pub const DEFAULT_TEMPLATES_DIR: &str = "email-templates";

#[derive(Clone, Copy)]
pub enum EmailTemplate {
    Verification,
    PasswordReset,
    Invitation,
}

impl EmailTemplate {
    fn kind(self) -> &'static str {
        match self {
            EmailTemplate::Verification => "verification",
            EmailTemplate::PasswordReset => "password_reset",
            EmailTemplate::Invitation => "invitation",
        }
    }

    fn file_name(self) -> String {
        format!("{}.tmpl", self.kind())
    }
}

/// Renders `template` with `vars` and sends it to `to` over SMTP. `log_url`
/// is the single templated link, logged alongside the template kind so the
/// existing dev-bypass warnings stay identifiable per email kind.
pub async fn send_templated_email(
    cfg: &Config,
    template: EmailTemplate,
    to: &str,
    log_url: &str,
    vars: &[(&str, &str)],
) -> Result<(), AppError> {
    let Some(smtp) = cfg.smtp.as_ref() else {
        if cfg.dev_allow_unverified_email_login {
            tracing::warn!(
                email = to,
                kind = template.kind(),
                url = log_url,
                "SMTP is not configured; skipping email in development bypass mode"
            );
            return Ok(());
        }
        return Err(AppError::Internal(anyhow::anyhow!(
            "SMTP is not configured"
        )));
    };

    let raw = read_template(cfg, template)?;
    let parsed = parse_template(&raw)?;
    let subject = render(parsed.subject, vars)?;
    let body = render(parsed.body, vars)?;
    let content_type = match parsed.content_type {
        Some("text/html") => ContentType::TEXT_HTML,
        _ => ContentType::TEXT_PLAIN,
    };

    let message = Message::builder()
        .from(
            smtp.from
                .parse()
                .map_err(|e| AppError::bad_request(format!("invalid SMTP from address: {e}")))?,
        )
        .to(to
            .parse()
            .map_err(|e| AppError::bad_request(format!("invalid email address: {e}")))?)
        .subject(subject.trim())
        .header(content_type)
        .body(body)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("build email: {e}")))?;

    let mailer = build_transport(smtp)?;
    if let Err(err) = mailer.send(message).await {
        if cfg.dev_allow_unverified_email_login {
            tracing::warn!(
                email = to,
                kind = template.kind(),
                url = log_url,
                error = %err,
                "SMTP send failed; skipping email in development bypass mode"
            );
            return Ok(());
        }
        return Err(AppError::Internal(anyhow::anyhow!(
            "send {} email: {err}",
            template.kind()
        )));
    }
    Ok(())
}

/// Checks the operator override directory first, then falls back to the
/// built-in default shipped at `DEFAULT_TEMPLATES_DIR`.
fn read_template(cfg: &Config, template: EmailTemplate) -> Result<String, AppError> {
    if let Some(dir) = &cfg.email_templates_dir {
        let override_path = Path::new(dir).join(template.file_name());
        if let Ok(contents) = std::fs::read_to_string(&override_path) {
            return Ok(contents);
        }
    }
    let default_path: PathBuf = Path::new(DEFAULT_TEMPLATES_DIR).join(template.file_name());
    std::fs::read_to_string(&default_path).map_err(|e| {
        AppError::Internal(anyhow::anyhow!(
            "read email template {}: {e}",
            default_path.display()
        ))
    })
}

#[derive(Debug)]
struct ParsedTemplate<'a> {
    subject: &'a str,
    content_type: Option<&'a str>,
    body: &'a str,
}

/// Parses a template file's header block (`Subject:` required,
/// `Content-Type:` optional, one per line) up to the first blank line, then
/// the body — the same shape as a raw RFC 5322 message, chosen so both stay
/// customizable without needing a second file per template.
fn parse_template(raw: &str) -> Result<ParsedTemplate<'_>, AppError> {
    let (header_block, body) = raw.split_once("\n\n").ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "email template must have a 'Subject: ...' line, a blank line, then the body"
        ))
    })?;

    let mut subject = None;
    let mut content_type = None;
    for line in header_block.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(value) = line.strip_prefix("Subject:") {
            subject = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("Content-Type:") {
            content_type = Some(value.trim());
        }
    }

    let subject = subject.ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!(
            "email template must have a 'Subject: ...' header line"
        ))
    })?;
    Ok(ParsedTemplate {
        subject,
        content_type,
        body,
    })
}

fn render(template_str: &str, vars: &[(&str, &str)]) -> Result<String, AppError> {
    let env = minijinja::Environment::new();
    let tmpl = env
        .template_from_str(template_str)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("parse email template: {e}")))?;
    let ctx = minijinja::Value::from_iter(
        vars.iter()
            .map(|(key, value)| (key.to_string(), value.to_string())),
    );
    tmpl.render(ctx)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("render email template: {e}")))
}

fn build_transport(smtp: &SmtpConfig) -> Result<AsyncSmtpTransport<Tokio1Executor>, AppError> {
    let mut builder = match smtp.tls {
        SmtpTls::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host),
        SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&smtp.host)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("smtp starttls: {e}")))?,
        SmtpTls::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp.host)
            .map_err(|e| AppError::Internal(anyhow::anyhow!("smtp tls: {e}")))?,
    }
    .port(smtp.port);

    if let (Some(username), Some(password)) = (&smtp.username, &smtp.password) {
        builder = builder.credentials(Credentials::new(username.clone(), password.clone()));
    }

    Ok(builder.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falls_back_to_default_template_when_no_override_dir_is_set() {
        let cfg = Config::for_tests();
        let raw = read_template(&cfg, EmailTemplate::Verification).expect("default template");
        let parsed = parse_template(&raw).expect("parse");
        assert_eq!(parsed.subject, "Verify your Atom account");
        assert_eq!(parsed.content_type, None);
    }

    #[test]
    fn override_file_takes_precedence_over_default() {
        let dir = tempfile_dir();
        std::fs::write(
            dir.join("verification.tmpl"),
            "Subject: Custom subject\nContent-Type: text/html\n\nCustom body {{ verification_url }}\n",
        )
        .unwrap();

        let mut cfg = Config::for_tests();
        cfg.email_templates_dir = Some(dir.to_string_lossy().to_string());

        let raw = read_template(&cfg, EmailTemplate::Verification).expect("overridden template");
        let parsed = parse_template(&raw).expect("parse");
        assert_eq!(parsed.subject, "Custom subject");
        assert_eq!(parsed.content_type, Some("text/html"));
        assert!(parsed.body.contains("Custom body"));

        // A template not present in the override dir still falls back to
        // the built-in default rather than failing.
        let raw = read_template(&cfg, EmailTemplate::Invitation).expect("default falls back");
        let parsed = parse_template(&raw).expect("parse");
        assert_eq!(parsed.subject, "You have been invited");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn parse_rejects_template_missing_subject_header() {
        let err = parse_template("no subject header\n\nbody").unwrap_err();
        assert!(format!("{err:?}").contains("Subject:"));
    }

    #[test]
    fn parse_rejects_template_missing_blank_line() {
        let err = parse_template("Subject: only one line").unwrap_err();
        assert!(format!("{err:?}").contains("blank line"));
    }

    #[test]
    fn renders_variables_into_template() {
        let rendered = render(
            "Hello {{ name }}, click {{ url }}",
            &[("name", "Ada"), ("url", "https://example.test")],
        )
        .expect("render");
        assert_eq!(rendered, "Hello Ada, click https://example.test");
    }

    fn tempfile_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "atom-mail-test-{}-{:?}",
            std::process::id(),
            std::time::Instant::now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
