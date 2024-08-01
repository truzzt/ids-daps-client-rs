pub struct ReqwestDapsClient {
    client: reqwest::Client,
}

#[async_trait::async_trait]
impl super::DapsClientRequest for ReqwestDapsClient {
    async fn get_certs(
        &self,
        url: &str,
    ) -> Result<jsonwebtoken::jwk::JwkSet, super::DapsHttpClientError> {
        // Send request
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| super::DapsHttpClientError::RedirectError(Box::new(e)))?;

        // Parse response
        let jwks = response
            .json::<jsonwebtoken::jwk::JwkSet>()
            .await
            .map_err(|e| super::DapsHttpClientError::JsonError(e.to_string()))?;
        Ok(jwks)
    }

    async fn request_token(
        &self,
        url: &str,
        form_values: &[(&str, &str)],
    ) -> Result<super::TokenResponse, super::DapsHttpClientError> {
        // Send request
        let response = self
            .client
            .post(url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .form(form_values)
            .send()
            .await
            .map_err(|e| super::DapsHttpClientError::RedirectError(Box::new(e)))?;

        // Check status
        if response.status() != reqwest::StatusCode::OK {
            let response_status = response.status();
            let response_text = response
                .text()
                .await
                .map_err(|e| super::DapsHttpClientError::TextError(e.to_string()))?;
            tracing::error!("Error: {} {:?}", response_status.as_str(), response_text);
            return Err(super::DapsHttpClientError::RequestFailed(
                response_status.as_u16(),
                response_text,
            ));
        }

        // Parse response
        let token = response
            .json::<super::TokenResponse>()
            .await
            .map_err(|e| super::DapsHttpClientError::JsonError(e.to_string()))?;
        Ok(token)
    }
}

impl Default for ReqwestDapsClient {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}
