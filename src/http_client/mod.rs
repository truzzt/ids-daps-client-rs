use crate::TokenResponse;

pub(crate) mod reqwest_client;

#[derive(Debug, thiserror::Error)]
pub enum DapsHttpClientError {
    #[error("HTTP request failed because of Status code {0}: {1}")]
    RequestFailed(u16, String),
    #[error("Error in sending HTTP request: {0}")]
    RedirectError(Box<dyn std::error::Error>),
    #[error("Error in parsing JSON response: {0}")]
    JsonError(String),
    #[error("Error in parsing response as text: {0}")]
    TextError(String),
}

#[async_trait::async_trait]
pub trait DapsClientRequest: Default {
    async fn get_certs(&self, url: &str) -> Result<jsonwebtoken::jwk::JwkSet, DapsHttpClientError>;
    async fn request_token(
        &self,
        url: &str,
        form_values: &[(&str, &str)],
    ) -> Result<TokenResponse, DapsHttpClientError>;
}
