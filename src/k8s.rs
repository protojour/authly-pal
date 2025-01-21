use std::collections::BTreeMap;

use anyhow::anyhow;
use k8s_openapi::{api::core::v1::Secret, ByteString};
use kube::{
    api::{ObjectMeta, Patch, PatchParams},
    Api, Client,
};
use rand::{rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};

use crate::Hex;

#[derive(Clone, Serialize, Deserialize)]
struct Key {
    version: Hex,
    plaintext: Hex,
}

pub async fn k8s_key(input: crate::Input) -> anyhow::Result<crate::Output> {
    let client = kube::Client::try_default().await.unwrap();
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), client.default_namespace());

    let secret_name = format!("authly-key-{}", input.key_id);

    if secret_api.get(&secret_name).await.is_err() {
        let secret = render_secret(Default::default(), &secret_name, &client);

        secret_api
            .patch(
                &secret_name,
                &PatchParams::apply("authly"),
                &Patch::Apply(secret),
            )
            .await?;
    }

    let secret = secret_api.get(&secret_name).await?;

    println!("{secret:#?}");

    let mut keys: BTreeMap<String, Key> = secret
        .data
        .into_iter()
        .flatten()
        .map(|(name, json)| {
            let key = serde_json::from_slice(&json.0)?;

            Ok((name, key))
        })
        .collect::<anyhow::Result<_>>()?;

    let (key, mutated) = if let Some(Hex(ciphertext)) = input.version {
        match find_dek(&keys, &ciphertext) {
            Some(key) => (key.clone(), false),
            None => return Err(anyhow!("ciphertext not found")),
        }
    } else {
        (create_dek(&mut keys)?, true)
    };

    if mutated {
        secret_api
            .patch(
                &secret_name,
                &PatchParams::apply("authly"),
                &Patch::Apply(render_secret(keys, &secret_name, &client)),
            )
            .await?;
    }

    Ok(crate::Output {
        key_id: input.key_id,
        plaintext: key.plaintext,
        version: key.version,
    })
}

fn find_dek<'k>(keys: &'k BTreeMap<String, Key>, version: &[u8]) -> Option<&'k Key> {
    keys.iter()
        .find(|(name, key)| name.starts_with("DEK") && key.version.0 == version)
        .map(|(_, key)| key)
}

fn create_dek(keys: &mut BTreeMap<String, Key>) -> anyhow::Result<Key> {
    let key_name = format!("DEK{}", keys.len());

    let mut ciphertext: [u8; 32] = [0; 32];
    let mut plaintext: [u8; 32] = [0; 32];

    OsRng.fill(ciphertext.as_mut_slice());
    OsRng.fill(plaintext.as_mut_slice());

    let key = Key {
        version: Hex(ciphertext.to_vec()),
        plaintext: Hex(plaintext.to_vec()),
    };

    keys.insert(key_name, key.clone());

    Ok(key)
}

fn render_secret(keys: BTreeMap<String, Key>, secret_name: &str, client: &Client) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_string()),
            namespace: Some(client.default_namespace().into()),
            annotations: Some(
                [(
                    "kubernetes.io/description".to_string(),
                    "Authly master key".to_string(),
                )]
                .into(),
            ),
            ..Default::default()
        },
        type_: None,
        string_data: None,
        data: Some(
            keys.into_iter()
                .map(|(name, key)| {
                    let json = serde_json::to_vec(&key).unwrap();
                    (name, ByteString(json))
                })
                .collect(),
        ),
        immutable: None,
    }
}
