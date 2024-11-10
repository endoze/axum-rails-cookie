# Axum Rails Cookie Extractor

![Build Status](https://github.com/endoze/axum-rails-cookie/actions/workflows/ci.yml/badge.svg?branch=master)
[![Coverage Status](https://coveralls.io/repos/github/endoze/axum-rails-cookie/badge.svg?branch=master)](https://coveralls.io/github/endoze/axum-rails-cookie?branch=master)
[![Crate](https://img.shields.io/crates/v/axum-rails-cookie.svg)](https://crates.io/crates/axum-rails-cookie)
[![Docs](https://docs.rs/axum-rails-cookie/badge.svg)](https://docs.rs/axum-rails-cookie)

Extract rails cookies in axum handlers.

## Installation

As a dependency of a Rust project:

```sh
cargo add axum-rails-cookie
```

## Library Usage

axum-rails-cookie is provided as a crate that you can use in your own code.

Cargo.toml:
```toml
[dependencies]
axum = "0.7.7"
tokio = {version = "1.41.0", features=["full"]}
anyhow = "1.0"
axum-macros = "0.4"
axum-rails-cookie = "0.1.0"
```

main.rs:
```rust , ignore
use axum::{routing::get, Extension, Router};
use axum_macros::debug_handler;
use axum_rails_cookie::{AppConfig, CookieAlgorithm, RailsCookie};

pub struct AppError(anyhow::Error);

impl axum::response::IntoResponse for AppError {
  fn into_response(self) -> axum::response::Response {
    (
      axum::http::StatusCode::INTERNAL_SERVER_ERROR,
      format!("Something went wrong: {}", self.0),
    )
      .into_response()
  }
}

impl<E> From<E> for AppError
where
  E: Into<anyhow::Error>,
{
  fn from(err: E) -> Self {
    Self(err.into())
  }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let config = CookieConfig::new(
    "_my_app_session_id", 
    "3e3500446d813ba4be17b9322927e6cdd11fd502777641bffa9ee7b60b82ddeb8315f5fcb01f5399c42eb106d88015c67ccc7499715144eb2700a953daa320a5",
    CookieAlgorithm::AesHmac,
  );

  let app = Router::new()
    .route("/", get(root_handler))
    .layer(Extension(config));

  let listen_address = format!("{}:{}", "0.0.0.0", "8000");
  println!("Listening on {}", listen_address);

  let listener = tokio::net::TcpListener::bind(listen_address).await?;

  axum::serve(listener, app).await?;

  Ok(())
}

#[debug_handler]
async fn root_handler(rails_cookie: RailsCookie) -> Result<String, AppError> {
  if let RailsCookie::Ok(cookie) = rails_cookie {
    return Ok(cookie);
  }

  Ok("No cookie found".into())
}
```

## Inpsiration

I wanted to be able to integrate axum based projects with existing rails applications and share
session data between the two.

## Security Notes

You should ensure that you never commit or track your secret key in your
repository if you choose to use this code to encrypt/decrypt rails session cookies in 
your code. You could use git ignored configuration files or environment variables to
store your secret key to ensure it is never committed.
