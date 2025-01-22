use std::env;

use anyhow::anyhow;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json,
};
use rand::{rngs::OsRng, Rng};
// use base64_serde::
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

mod aws;
mod k8s;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy)]
enum KeyPlatform {
    AwsKms,
    K8sInsecure,
    DangerEncryptionDisabled,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::from("info"))
        .init();

    info!("🧠 Authly PAL v{VERSION}");

    let key_platform = if env::var("AWS").is_ok() {
        info!("Using AWS KMS key backend");
        KeyPlatform::AwsKms
    } else if env::var("K8S_INSECURE").is_ok() {
        warn!("Using Kubernetes insecure secret backend");
        KeyPlatform::K8sInsecure
    } else if env::var("DANGER_ENCRYPTION_DISABLED").is_ok() {
        for _ in 0..10 {
            warn!("DANGER: AUTHLY ENCRYPTION COMPLETELY DISABLED");
        }
        KeyPlatform::DangerEncryptionDisabled
    } else {
        return Err(anyhow!("no backend specified"));
    };

    let app = axum::Router::new()
        .route("/api/v0/key", post(v0_post_key))
        .with_state(key_platform);

    let shutdown_signal = async move {
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install signal handler")
                .recv()
                .await;
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate => {}
        }
    };

    let listener = TcpListener::bind("0.0.0.0:6666").await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    Ok(())
}

#[derive(Deserialize)]
struct Input {
    key_id: String,

    // If this is null, creates a new key version
    version: Option<Hex>,
}

#[derive(Serialize)]
struct Output {
    key_id: String,
    version: Hex,
    plaintext: Hex,
}

enum Error {
    Unknown,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let msg = match self {
            Self::Unknown => "unknown",
        };

        (StatusCode::INTERNAL_SERVER_ERROR, Json(msg)).into_response()
    }
}

/// Handle AES key request.
///
/// Only the cluster leader can call this, to avoid concurrency issues.
async fn v0_post_key(
    State(backend): State<KeyPlatform>,
    Json(input): Json<Input>,
) -> Result<Json<Output>, Error> {
    let output = match backend {
        KeyPlatform::AwsKms => aws::aws_key(input).await.map_err(|_| Error::Unknown)?,
        KeyPlatform::K8sInsecure => k8s::k8s_key(input).await.map_err(|_| Error::Unknown)?,
        KeyPlatform::DangerEncryptionDisabled => {
            let key = match &input.version {
                Some(Hex(version)) => version.clone(),
                None => {
                    let mut key: [u8; 32] = [0; 32];
                    OsRng.fill(key.as_mut_slice());
                    key.to_vec()
                }
            };

            Output {
                key_id: input.key_id,
                version: Hex(key.clone()),
                plaintext: Hex(key),
            }
        }
    };

    Ok(Json(output))
}

#[derive(Clone, Serialize, Deserialize)]
struct Hex(
    #[serde(
        serialize_with = "hex::serde::serialize",
        deserialize_with = "hex::serde::deserialize"
    )]
    pub Vec<u8>,
);
