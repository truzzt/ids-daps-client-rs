use std::borrow::Cow;

/// Configuration for the DAPS client.
#[derive(Debug, derive_builder::Builder)]
#[builder(setter(into), build_fn(validate = "Self::validate"))]
#[allow(clippy::module_name_repetitions)]
pub struct DapsConfig<'a> {
    /// The URL for the request of a DAPS token.
    pub(super) token_url: Cow<'a, str>,
    /// The URL for the request of the certificates for validation.
    pub(super) certs_url: Cow<'a, str>,
    /// The local path to the private key file.
    pub(super) private_key: Cow<'a, std::path::Path>,
    /// The password for the private key file.
    pub(super) private_key_password: Option<Cow<'a, str>>,
    /// The scope for the DAPS token.
    pub(super) scope: Cow<'a, str>,
    /// The time-to-live for the certificates cache in seconds.
    pub(super) certs_cache_ttl: u64,
}

impl DapsConfigBuilder<'_> {
    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.token_url.is_none() {
            return Err("Token URL is empty".to_string());
        } else if let Some(token_url) = self.token_url.clone() {
            token_url
                .parse::<url::Url>()
                .map_err(|e| format!("Token URL is invalid: {e}"))?;
        }
        if self.certs_url.is_none() {
            return Err("Certs URL is empty".to_string());
        } else if let Some(certs_url) = self.certs_url.clone() {
            certs_url
                .parse::<url::Url>()
                .map_err(|e| format!("Certs URL is invalid: {e}"))?;
        }
        if self.private_key.is_none() {
            return Err("Private key path is empty".to_string());
        }
        if self.private_key_password.is_none() {
            return Err("Private key password is empty".to_string());
        }
        if self.scope.is_none() {
            return Err("Scope is empty".to_string());
        }
        Ok(())
    }
}
