use aws_config::BehaviorVersion;
use aws_sdk_kms::types::{DataKeySpec, KeySpec, KeyUsageType, OriginType};

pub async fn aws_key(input: crate::Input) -> anyhow::Result<crate::Output> {
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let client = aws_sdk_kms::Client::new(&config);

    client.create_grant();

    let create_key_output = client
        .create_key()
        .description("Authly master key")
        .key_usage(KeyUsageType::EncryptDecrypt)
        .key_spec(KeySpec::SymmetricDefault)
        .origin(OriginType::AwsKms)
        .send()
        .await?;

    let metadata = create_key_output.key_metadata.unwrap();
    let key_id = metadata.key_id();

    // metadata.encryption_algorithms

    let key = client
        .generate_data_key()
        .key_id(key_id)
        .key_spec(DataKeySpec::Aes256)
        .send()
        .await?;

    let _master_key_plaintext = key.plaintext.unwrap();
    let master_key_ciphertext = key.ciphertext_blob.unwrap();
    // use plaintext key to encrypt DEK

    let _master_key_plaintext = client
        .decrypt()
        .ciphertext_blob(master_key_ciphertext)
        .send()
        .await?;

    // Ok(())
    todo!()
}
