#![deny(unsafe_code, rust_2018_idioms, clippy::unwrap_used)]
#![warn(rust_2024_compatibility, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod cert;
mod http_client;

use std::borrow::Cow;

#[derive(Debug, serde::Serialize, Clone)]
struct TokenClaims {
    #[serde(rename = "@type")]
    type_: String,
    #[serde(rename = "@context")]
    context_: String,
    iss: String,
    sub: String,
    id: String,
    jti: String,
    aud: String,
    iat: i64,
    exp: i64,
    nbf: i64,
}

/// Token response from the DAPS.
#[derive(Debug, serde::Deserialize, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: Option<String>,
}

/// Claims within the DAT token.
#[derive(Debug, serde::Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
pub struct DatClaims {
    #[serde(rename = "@type")]
    type_: String,
    #[serde(rename = "@context")]
    context_: String,
    referring_connector: String,
    security_profile: String,
    #[serde(rename = "iat")]
    issued_at: i64,
    #[serde(rename = "exp")]
    expires_at: i64,
    #[serde(rename = "nbf")]
    not_before: i64,
    #[serde(rename = "sub")]
    subject: String,
    #[serde(rename = "aud")]
    audience: String,
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "jti")]
    jwt_id: String,
}

#[derive(thiserror::Error, Debug)]
pub enum DapsError {
    #[error("http client error: {0}")]
    DapsHttpClient(#[from] http_client::DapsHttpClientError),
    #[error("jwt error")]
    InvalidToken,
}

/// Configuration for the DAPS client.
#[derive(Debug, derive_builder::Builder)]
#[builder(setter(into), build_fn(validate = "Self::validate"))]
pub struct DapsConfig<'a> {
    /// The URL for the request of a DAPS token.
    token_url: Cow<'a, str>,
    /// The URL for the request of the certificates for validation.
    certs_url: Cow<'a, str>,
    /// The local path to the private key file.
    private_key: Cow<'a, std::path::Path>,
    /// The password for the private key file.
    private_key_password: Option<Cow<'a, str>>,
    /// The scope for the DAPS token.
    scope: Cow<'a, str>,
    /// The time-to-live for the certificates cache in seconds.
    certs_cache_ttl: i64,
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

/// A cache for the certificates of the DAPS.
struct CertificatesCache {
    stored: chrono::DateTime<chrono::Utc>,
    jwks: jsonwebtoken::jwk::JwkSet,
}

/// An alias for the DAPS client using the Reqwest HTTP client.
pub type ReqwestDapsClient<'a> = DapsClient<'a, http_client::reqwest_client::ReqwestDapsClient>;

/// The main struct of this crate. It provides the functionality to request and validate DAT tokens
/// from a DAPS.
pub struct DapsClient<'a, C> {
    /// The HTTP client to use for requests. It is generic over the actual implementation.
    client: C,
    /// The subject of the client.
    sub: Cow<'a, str>,
    /// The URL for the request of the certificates for validation.
    certs_url: String,
    /// The URL for the request of a DAPS token.
    token_url: String,
    /// The scope for the DAPS token.
    scope: String,
    /// The encoding key for the JWT.
    encoding_key: jsonwebtoken::EncodingKey,
    /// The UUID context for the JWT. To generate ordered UUIDs (v7).
    uuid_context: uuid::ContextV7,
    /// A cache for the certificates of the DAPS.
    certs_cache: async_lock::RwLock<CertificatesCache>,
    /// TTL for the cache.
    cache_ttl: chrono::Duration,
}

impl<C> DapsClient<'_, C>
where
    C: http_client::DapsClientRequest,
{
    /// Creates a new DAPS client based on the given configuration.
    #[must_use]
    pub fn new(config: &DapsConfig<'_>) -> Self {
        // Read sub and private key from file
        let (ski_aki, private_key) = cert::ski_aki_and_private_key_from_file(
            config.private_key.as_ref(),
            config.private_key_password.as_deref().unwrap_or(""),
        )
        .expect("Reading SKI:AKI failed");

        // Use private key to create the encoding key
        let encoding_key = jsonwebtoken::EncodingKey::from_rsa_der(private_key.as_ref());

        Self {
            client: C::default(),
            sub: ski_aki,
            scope: config.scope.to_string(),
            certs_url: config.certs_url.to_string(),
            token_url: config.token_url.to_string(),
            encoding_key,
            uuid_context: uuid::ContextV7::new(),
            certs_cache: async_lock::RwLock::new(CertificatesCache {
                stored: chrono::DateTime::from_timestamp(0, 0).expect("This is a valid timestamp"),
                jwks: jsonwebtoken::jwk::JwkSet { keys: Vec::new() },
            }),
            cache_ttl: chrono::Duration::seconds(config.certs_cache_ttl),
        }
    }

    /// Validates a DAT token against the DAPS.
    pub async fn validate_dat(
        &self,
        token: &str,
    ) -> Result<jsonwebtoken::TokenData<DatClaims>, DapsError> {
        // Get JWKS from DAPS
        let jwks = self.get_certs().await?;

        // Set up validation configuration
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.sub = Some(self.sub.to_string());
        validation.set_audience(&["idsc:IDS_CONNECTORS_ALL"]);
        validation.set_required_spec_claims(&["exp", "nbf", "aud", "iss", "sub"]);

        // Decode against all keys
        let validation_results: Vec<jsonwebtoken::TokenData<_>> = jwks
            .keys
            .iter()
            .filter_map(|jwk| {
                if let Ok(jwk) = jsonwebtoken::DecodingKey::from_jwk(jwk) {
                    let result = jsonwebtoken::decode(token, &jwk, &validation);
                    tracing::debug!("Validation result: {:?}", result);
                    result.ok()
                } else {
                    None
                }
            })
            .collect();

        // Return first positive validation result
        validation_results
            .first()
            .ok_or(DapsError::InvalidToken)
            .cloned()
    }

    /// Requests a DAT token from the DAPS.
    pub async fn request_dat(&self) -> Result<String, DapsError> {
        // Get the current timestamp for the claims
        let now = chrono::Utc::now();
        let now_secs = now.timestamp();
        let now_subsec_nanos = now.timestamp_subsec_nanos();
        #[allow(clippy::cast_sign_loss)]
        let uuid_timestamp =
            uuid::Timestamp::from_unix(&self.uuid_context, now_secs as u64, now_subsec_nanos);

        // Create a JWT for the client assertion
        let header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        let claims = TokenClaims {
            context_: "https://w3id.org/idsa/contexts/context.jsonld".to_string(),
            type_: "ids:DatRequestToken".to_string(),
            jti: uuid::Uuid::new_v7(uuid_timestamp).hyphenated().to_string(),
            iss: self.sub.to_string(),
            sub: self.sub.to_string(),
            id: self.sub.to_string(),
            aud: self.scope.clone(),
            iat: now_secs,
            exp: now_secs + 3600,
            nbf: now_secs,
        };
        // Encode token
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .expect("Token signing failed. There must be something wrong with the private key.");

        tracing::debug!("Issued TokenRequest (requestDAT): {}", token);

        let response = self
            .client
            .request_token(
                self.token_url.as_ref(),
                &[
                    ("grant_type", "client_credentials"),
                    ("scope", "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL"),
                    (
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    ),
                    ("client_assertion", &token),
                ],
            )
            .await?;

        Ok(response.access_token)
    }

    /// Updates the certificate cache with the Certificates requested from the DAPS.
    async fn update_cert_cache(&self) -> Result<jsonwebtoken::jwk::JwkSet, DapsError> {
        let jwks = self.client.get_certs(self.certs_url.as_ref()).await?;
        let mut cache = self.certs_cache.write().await;
        cache.jwks = jwks;
        cache.stored = chrono::Utc::now();
        Ok(cache.jwks.clone())
    }

    /// Returns the certificates from the cache or updates the cache if it is outdated.
    async fn get_certs(&self) -> Result<jsonwebtoken::jwk::JwkSet, DapsError> {
        let now = chrono::Utc::now();
        tracing::debug!("Checking cache...");

        let cache = self.certs_cache.read().await;
        if cache.stored + self.cache_ttl < now {
            tracing::info!("Cache is outdated, updating...");
            // Cache is outdated, drop lock
            drop(cache);

            // Update cache
            let jwks = self.update_cert_cache().await;
            tracing::debug!("Cache updated");
            jwks
        } else {
            tracing::debug!("Cache is up-to-date");
            Ok(cache.jwks.clone())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn integration_test() {
        use testcontainers::runners::AsyncRunner;

        // Setting up logger to debug issues
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("ids_daps=DEBUG"))
            .init();

        // Starting test DAPS
        let image = testcontainers::GenericImage::new("ghcr.io/ids-basecamp/test-daps", "0.0.1"); // TODO: Change to correct image
        let container = image
            .with_exposed_port(8080.into()) // will default to TCP protocol
            .with_wait_for(testcontainers::core::WaitFor::message_on_stdout(
                "Started Application in",
            )) // TODO: Change to correct message
            .start()
            .await?;

        // Create DAPS config
        let config = DapsConfigBuilder::create_empty()
            .certs_url(
                "http://localhost:8080/realms/DAPS/protocol/openid-connect/certs" // TODO: Change to correct URL
                    .to_string(),
            )
            .token_url(
                "http://localhost:8080/realms/DAPS/protocol/openid-connect/token", // TODO: Change to correct URL
            )
            .private_key(std::path::Path::new(
                "./testdata/connector-certificate.p12", // TODO: Put certificate into the /testdata folder (from root of the repository)
            ))
            .private_key_password(Some(Cow::from("Password1")))
            .scope(Cow::from(
                "https://daps.dev.mobility-dataspace.eu/realms/DAPS", // TODO: Check if scope can stay the same
            ))
            .certs_cache_ttl(1)
            .build()
            .expect("Failed to build DapsConfig");

        // Create DAPS client
        let client: ReqwestDapsClient<'_> = DapsClient::new(&config);

        // Now the test really starts...
        // Request a DAT token
        let dat = client.request_dat().await.unwrap();
        println!("{:?}", dat);

        // Validate the DAT token
        let cache1_start = std::time::Instant::now();
        assert!(client.validate_dat(&dat).await.is_ok());
        println!("First validation took {:?}", cache1_start.elapsed());

        // Checking again to use cache
        let cache2_start = std::time::Instant::now();
        assert!(client.validate_dat(&dat).await.is_ok());
        println!("Second validation took {:?}", cache2_start.elapsed());

        // Wait for cache to expire
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        // Now the cache should be outdated
        let cache3_start = std::time::Instant::now();
        assert!(client.validate_dat(&dat).await.is_ok());
        println!("Third validation took {:?}", cache3_start.elapsed());
    }
}
