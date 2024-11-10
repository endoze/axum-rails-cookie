//!
#![doc = include_str!("../README.md")]

use axum::{
  async_trait,
  extract::{Extension, FromRequestParts},
  http::request::Parts,
  RequestPartsExt,
};
use axum_extra::extract::CookieJar;
use message_verifier::{AesGcmEncryptor, AesHmacEncryptor, DerivedKeyParams, Encryptor};
use std::convert::Infallible;

/// Encryption salt used during encryption key derivation for encrypted cookies.
const ENCRYPTION_SALT: &str = "encrypted cookie";
/// Signing salt used during signed encrypted key derivation for signed encrypted cookies.
const SIGNING_SALT: &str = "signed encrypted cookie";

/// Represents different errors that can occur during cookie retrieval.
#[derive(thiserror::Error, Debug)]
pub enum RailsCookieError {
  /// Error retrieving CookieConfig
  #[error("Failed to extract Config")]
  Config,

  /// Error retrieving cookie jar
  #[error("Failed to get cookie jar")]
  CookieJar,

  /// Error retrieving cookie
  #[error("Failed to get cookie")]
  CookieRetrieval,

  /// Error creating cookie decryptor
  #[error("Failed to create decryptor")]
  DecryptorCreation,

  /// Error decrypting cookie
  #[error("Failed to decrypt cookie data")]
  Decryption,

  /// Error parsing decrypted cookie
  #[error("Failed to parse valid utf8 from cookie data")]
  CookieParse,
}

#[allow(unused)]
#[derive(Debug, Clone)]
pub enum CookieAlgorithm {
  AesHmac,
  AesGcm,
}

/// Represents values used during cookie retrieval.
///
/// # Example
///
/// You can create a `CookieConfig` using the following code:
///
/// ```
/// use axum_rails_cookie::{CookieConfig, CookieAlgorithm};
///
/// let name = "_my_app_session_id";
/// let secret = "3b53beba93922c29b3c335051f79e41c63fe626834d5a4a7ce96ebd189010063";
/// let algorithm = CookieAlgorithm::AesHmac;
/// let encryptor = CookieConfig::new(name, secret, algorithm);
/// ```
#[derive(Clone)]
pub struct CookieConfig {
  name: &'static str,
  secret: &'static str,
  algorithm: CookieAlgorithm,
}

impl CookieConfig {
  pub fn new(name: &'static str, secret: &'static str, algorithm: CookieAlgorithm) -> Self {
    CookieConfig {
      name,
      secret,
      algorithm,
    }
  }
}

impl std::fmt::Debug for CookieConfig {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "CookieConfig {{}}")
  }
}

impl std::fmt::Display for CookieConfig {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{:?}", self)
  }
}

/// Represents the success or failure of retrieving a rails cookie.
#[derive(Debug)]
pub enum RailsCookie {
  Ok(String),
  Err(RailsCookieError),
}

#[async_trait]
impl<S> FromRequestParts<S> for RailsCookie
where
  S: Send + Sync + 'static,
{
  type Rejection = Infallible;

  async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
    let Ok(Extension(config)): Result<Extension<CookieConfig>, _> =
      Extension::from_request_parts(parts, state).await
    else {
      return Ok(RailsCookie::Err(RailsCookieError::Config));
    };

    let Ok(cookie_jar) = parts.extract::<CookieJar>().await else {
      return Ok(RailsCookie::Err(RailsCookieError::CookieJar));
    };

    let Some(cookie) = cookie_jar.get(config.name) else {
      return Ok(RailsCookie::Err(RailsCookieError::CookieRetrieval));
    };

    let dkp = DerivedKeyParams::default();

    let encryptor: Box<dyn Encryptor> = match config.algorithm {
      CookieAlgorithm::AesHmac => {
        let encryptor: Result<AesHmacEncryptor, _> =
          AesHmacEncryptor::new(config.secret, ENCRYPTION_SALT, SIGNING_SALT, dkp);

        match encryptor {
          Ok(value) => Box::new(value),
          Err(_) => return Ok(RailsCookie::Err(RailsCookieError::DecryptorCreation)),
        }
      }
      CookieAlgorithm::AesGcm => {
        let encryptor: Result<AesGcmEncryptor, _> =
          AesGcmEncryptor::new(config.secret, ENCRYPTION_SALT, dkp);

        match encryptor {
          Ok(value) => Box::new(value),
          Err(_) => return Ok(RailsCookie::Err(RailsCookieError::DecryptorCreation)),
        }
      }
    };

    let Ok(decrypted_value) = encryptor.decrypt_and_verify(cookie.value()) else {
      return Ok(RailsCookie::Err(RailsCookieError::Decryption));
    };

    let Ok(decrypted_value) = String::from_utf8(decrypted_value) else {
      return Ok(RailsCookie::Err(RailsCookieError::CookieParse));
    };

    Ok(RailsCookie::Ok(decrypted_value))
  }
}

#[cfg(test)]
mod tests {
  use crate::{CookieAlgorithm, CookieConfig, RailsCookie, ENCRYPTION_SALT, SIGNING_SALT};
  use axum::{
    body::{to_bytes, Body},
    extract::Extension,
    http::{header, HeaderMap, Request},
    response::Response,
    routing::get,
    Router,
  };
  use axum_extra::extract::cookie::Cookie;
  use axum_macros::debug_handler;
  use message_verifier::{AesGcmEncryptor, AesHmacEncryptor, DerivedKeyParams, Encryptor};
  use tower::ServiceExt;

  /// Used to configure generate_app_and_request behavior in tests
  struct AppRequestConfig {
    cookie_name: String,
    include_config: bool,
    include_cookie_header: bool,
    encryption_salt: String,
    cookie_algorithm: CookieAlgorithm,
  }

  /// Axum handler function to simulate usage of RailsCookie extractor.
  #[debug_handler]
  async fn test_handler(rails_cookie: RailsCookie) -> Result<String, String> {
    match rails_cookie {
      RailsCookie::Ok(cookie) => Ok(cookie),
      RailsCookie::Err(err) => Err(err.to_string()),
    }
  }

  /// Generate an encrypted cookie as a string.
  ///
  /// # Arguments
  /// * `message` - Cookie data to be encrypted
  /// * `secret` - Secret to derive encryption key from
  /// * `encryption_salt` - Secret to derive signing key from
  /// * `cookie_alg` - Algorithm to use for cookie encryption
  fn generate_encrypted_cookie(
    message: &str,
    secret: &str,
    encryption_salt: &str,
    cookie_alg: CookieAlgorithm,
  ) -> String {
    let dkp = DerivedKeyParams::default();
    let encryptor: Box<dyn Encryptor> = match cookie_alg {
      CookieAlgorithm::AesHmac => {
        let encryptor = AesHmacEncryptor::new(secret, encryption_salt, SIGNING_SALT, dkp).unwrap();
        Box::new(encryptor)
      }
      CookieAlgorithm::AesGcm => {
        let encryptor = AesGcmEncryptor::new(secret, encryption_salt, dkp).unwrap();
        Box::new(encryptor)
      }
    };

    encryptor.encrypt_and_sign(message).unwrap()
  }

  /// Generates an axum router and request based on the AppRequestConfig param.
  ///
  /// # Arguments
  /// * `app_request_config` - Configuration that describes axum router and request behavior
  fn generate_app_and_request(app_request_config: AppRequestConfig) -> (Router, Request<Body>) {
    let secret_key_base = "3b53beba93922c29b3c335051f79e41c63fe626834d5a4a7ce96ebd189010063";
    let encrypted_signed_cookie = generate_encrypted_cookie(
      "hello world",
      secret_key_base,
      &app_request_config.encryption_salt,
      app_request_config.cookie_algorithm.clone(),
    );
    let config = CookieConfig::new(
      "test_cookie",
      secret_key_base,
      app_request_config.cookie_algorithm,
    );

    let app = if app_request_config.include_config {
      Router::new()
        .route("/", get(test_handler))
        .layer(Extension(config))
    } else {
      Router::new().route("/", get(test_handler))
    };

    let request = if app_request_config.include_cookie_header {
      let cookie = Cookie::new(app_request_config.cookie_name, encrypted_signed_cookie);
      let mut headers = HeaderMap::new();
      headers.insert(header::COOKIE, cookie.to_string().parse().unwrap());

      Request::builder()
        .uri("/")
        .header(header::COOKIE, cookie.to_string())
        .body(Body::empty())
        .unwrap()
    } else {
      Request::builder().uri("/").body(Body::empty()).unwrap()
    };

    (app, request)
  }

  /// Gets the request body of an http request as a UTF8 string.
  ///
  /// # Arguments
  /// * `response` - Response body from an axum request
  async fn get_response_body(response: Response<Body>) -> String {
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    String::from_utf8(body.to_vec()).unwrap()
  }

  mod cookie_config {
    use crate::{CookieAlgorithm, CookieConfig};

    #[test]
    fn test_config_does_not_expose_details_when_printed() {
      let cookie_config = CookieConfig::new(
        "_some_app_session_id",
        "3b53beba93922c29b3c335051f79e41c63fe626834d5a4a7ce96ebd189010063",
        CookieAlgorithm::AesHmac,
      );

      let result = format!("{}", cookie_config);
      let expected = "CookieConfig {}".to_string();

      assert_eq!(expected, result);
    }
  }

  mod aes_hmac {
    use super::*;

    #[tokio::test]
    async fn test_valid_cookie_extraction() {
      let (app, request) = generate_app_and_request(AppRequestConfig {
        cookie_name: "test_cookie".into(),
        include_config: true,
        include_cookie_header: true,
        encryption_salt: ENCRYPTION_SALT.to_string(),
        cookie_algorithm: CookieAlgorithm::AesHmac,
      });
      let response = app.oneshot(request).await.unwrap();

      assert_eq!(response.status(), 200);

      let body = get_response_body(response).await;

      assert_eq!(body, "hello world");
    }

    #[tokio::test]
    async fn test_invalid_cookie_extraction() {
      let (app, request) = generate_app_and_request(AppRequestConfig {
        cookie_name: "does_not_exist".into(),
        include_config: true,
        include_cookie_header: true,
        encryption_salt: ENCRYPTION_SALT.to_string(),
        cookie_algorithm: CookieAlgorithm::AesHmac,
      });
      let response = app.oneshot(request).await.unwrap();

      assert_eq!(response.status(), 200);

      let body = get_response_body(response).await;

      assert_eq!(body, "Failed to get cookie");
    }

    #[tokio::test]
    async fn test_missing_app_config_extension_extraction() {
      let (app, request) = generate_app_and_request(AppRequestConfig {
        cookie_name: "test_cookie".into(),
        include_config: false,
        include_cookie_header: true,
        encryption_salt: ENCRYPTION_SALT.to_string(),
        cookie_algorithm: CookieAlgorithm::AesHmac,
      });
      let response = app.oneshot(request).await.unwrap();

      assert_eq!(response.status(), 200);

      let body = get_response_body(response).await;

      assert_eq!(body, "Failed to extract Config");
    }

    #[tokio::test]
    async fn test_missing_cookie_header_extraction() {
      let (app, request) = generate_app_and_request(AppRequestConfig {
        cookie_name: "test_cookie".into(),
        include_config: true,
        include_cookie_header: false,
        encryption_salt: ENCRYPTION_SALT.to_string(),
        cookie_algorithm: CookieAlgorithm::AesHmac,
      });
      let response = app.oneshot(request).await.unwrap();

      assert_eq!(response.status(), 200);

      let body = get_response_body(response).await;

      assert_eq!(body, "Failed to get cookie");
    }

    #[tokio::test]
    async fn test_incorrect_encryption_salt_extraction() {
      let (app, request) = generate_app_and_request(AppRequestConfig {
        cookie_name: "test_cookie".into(),
        include_config: true,
        include_cookie_header: true,
        encryption_salt: "".to_string(),
        cookie_algorithm: CookieAlgorithm::AesHmac,
      });
      let response = app.oneshot(request).await.unwrap();

      assert_eq!(response.status(), 200);

      let body = get_response_body(response).await;

      assert_eq!(body, "Failed to decrypt cookie data");
    }
  }

  mod aes_gcm {
    use super::*;

    #[tokio::test]
    async fn test_valid_cookie_extraction() {
      let (app, request) = generate_app_and_request(AppRequestConfig {
        cookie_name: "test_cookie".into(),
        include_config: true,
        include_cookie_header: true,
        encryption_salt: ENCRYPTION_SALT.to_string(),
        cookie_algorithm: CookieAlgorithm::AesGcm,
      });
      let response = app.oneshot(request).await.unwrap();

      assert_eq!(response.status(), 200);

      let body = get_response_body(response).await;

      assert_eq!(body, "hello world");
    }

    #[tokio::test]
    async fn test_invalid_cookie_extraction() {
      let (app, request) = generate_app_and_request(AppRequestConfig {
        cookie_name: "does_not_exist".into(),
        include_config: true,
        include_cookie_header: true,
        encryption_salt: ENCRYPTION_SALT.to_string(),
        cookie_algorithm: CookieAlgorithm::AesGcm,
      });
      let response = app.oneshot(request).await.unwrap();

      assert_eq!(response.status(), 200);

      let body = get_response_body(response).await;

      assert_eq!(body, "Failed to get cookie");
    }

    #[tokio::test]
    async fn test_missing_app_config_extension_extraction() {
      let (app, request) = generate_app_and_request(AppRequestConfig {
        cookie_name: "test_cookie".into(),
        include_config: false,
        include_cookie_header: true,
        encryption_salt: ENCRYPTION_SALT.to_string(),
        cookie_algorithm: CookieAlgorithm::AesGcm,
      });
      let response = app.oneshot(request).await.unwrap();

      assert_eq!(response.status(), 200);

      let body = get_response_body(response).await;

      assert_eq!(body, "Failed to extract Config");
    }

    #[tokio::test]
    async fn test_missing_cookie_header_extraction() {
      let (app, request) = generate_app_and_request(AppRequestConfig {
        cookie_name: "test_cookie".into(),
        include_config: true,
        include_cookie_header: false,
        encryption_salt: ENCRYPTION_SALT.to_string(),
        cookie_algorithm: CookieAlgorithm::AesGcm,
      });
      let response = app.oneshot(request).await.unwrap();

      assert_eq!(response.status(), 200);

      let body = get_response_body(response).await;

      assert_eq!(body, "Failed to get cookie");
    }

    #[tokio::test]
    async fn test_incorrect_encryption_salt_extraction() {
      let (app, request) = generate_app_and_request(AppRequestConfig {
        cookie_name: "test_cookie".into(),
        include_config: true,
        include_cookie_header: true,
        encryption_salt: "".to_string(),
        cookie_algorithm: CookieAlgorithm::AesGcm,
      });
      let response = app.oneshot(request).await.unwrap();

      assert_eq!(response.status(), 200);

      let body = get_response_body(response).await;

      assert_eq!(body, "Failed to decrypt cookie data");
    }
  }
}
