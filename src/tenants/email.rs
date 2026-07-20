use crate::{config::Config, error::AppError, mail};

pub(crate) async fn send_invitation_email(
    cfg: &Config,
    email: &str,
    redirect_url: &str,
    token: &str,
) -> Result<(), AppError> {
    let invitation_url = url_with_params(redirect_url, &[("token", token)]);
    mail::send_templated_email(
        cfg,
        mail::EmailTemplate::Invitation,
        email,
        &invitation_url,
        &[("invitation_url", invitation_url.as_str())],
    )
    .await
}

fn url_with_params(base: &str, params: &[(&str, &str)]) -> String {
    match url::Url::parse(base) {
        Ok(mut parsed) => {
            {
                let mut pairs = parsed.query_pairs_mut();
                for (key, value) in params {
                    if !value.is_empty() {
                        pairs.append_pair(key, value);
                    }
                }
            }
            parsed.to_string()
        }
        Err(_) => {
            let mut url = base.to_string();
            let mut first = !url.contains('?');
            for (key, value) in params {
                if !value.is_empty() {
                    url.push(if first { '?' } else { '&' });
                    first = false;
                    url.push_str(key);
                    url.push('=');
                    url.push_str(value);
                }
            }
            url
        }
    }
}
