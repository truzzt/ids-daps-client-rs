//! Cache for the certificates of the DAPS Client.

/// An error that can occur when accessing the `CertificatesCache`.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum CertificatesCacheError {
    #[error("Cache is outdated")]
    Outdated,
    #[error("Cache is empty")]
    Empty,
}

/// A cache for the certificates of the DAPS.
#[derive(Debug, Default)]
pub(crate) struct CertificatesCache {
    /// The cache of certificates.
    inner: async_lock::RwLock<Option<CertificatesCacheStorage>>,
    /// The TTL of the cache.
    ttl: std::time::Duration,
}

impl CertificatesCache {
    #[must_use]
    pub(crate) fn new(ttl: std::time::Duration) -> Self {
        Self {
            ttl,
            ..Default::default()
        }
    }

    pub(crate) async fn get(&self) -> Result<jsonwebtoken::jwk::JwkSet, CertificatesCacheError> {
        let cache = self.inner.read().await;
        if let Some(cache) = &*cache {
            if cache.stored + self.ttl < chrono::Utc::now() {
                Err(CertificatesCacheError::Outdated)
            } else {
                Ok(cache.jwks.clone())
            }
        } else {
            Err(CertificatesCacheError::Empty)
        }
    }

    pub(crate) async fn update(
        &self,
        jwks: jsonwebtoken::jwk::JwkSet,
    ) -> Result<jsonwebtoken::jwk::JwkSet, CertificatesCacheError> {
        let mut cache = self.inner.write().await;
        let new_cache = CertificatesCacheStorage {
            jwks: jwks.clone(),
            stored: chrono::Utc::now(),
        };
        *cache = Some(new_cache);

        Ok(jwks)
    }
}

/// The storage of the cache.
#[derive(Debug)]
struct CertificatesCacheStorage {
    /// Timestamp of the last storage of the certificates.
    stored: chrono::DateTime<chrono::Utc>,
    /// The cache of certificates.
    jwks: jsonwebtoken::jwk::JwkSet,
}

#[cfg(test)]
mod test {

    #[tokio::test]
    async fn certificate_cache() {
        use super::*;

        let cache = CertificatesCache::new(std::time::Duration::from_secs(1));
        assert_eq!(Err(CertificatesCacheError::Empty), cache.get().await);

        let jwks = jsonwebtoken::jwk::JwkSet { keys: vec![] };
        cache.update(jwks.clone()).await.unwrap();
        assert_eq!(Ok(jwks), cache.get().await);

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        assert_eq!(Err(CertificatesCacheError::Outdated), cache.get().await);
    }
}
