use anyhow::anyhow;
use hexhex::hex_literal;
use rand::{rngs::OsRng, Rng};

use crate::{Hex, Output};

struct Key {
    ver: &'static [u8; 32],
    key: &'static [u8; 32],
}

pub fn key(input: crate::Input) -> anyhow::Result<crate::Output> {
    let key = match input.version {
        Some(Hex(version)) => KEYS
            .iter()
            .find(|key| key.ver == version.as_slice())
            .ok_or_else(|| anyhow!("invalid version"))?,
        None => &KEYS[OsRng.gen_range(0..KEYS.len())],
    };

    Ok(Output {
        key_id: input.key_id,
        version: Hex(key.ver.to_vec()),
        plaintext: Hex(key.key.to_vec()),
    })
}

/// This insecure implementation supports rotation between the following static keys
const KEYS: [Key; 16] = [
    Key {
        ver: hex_literal!("0eab660a37d58effacd60bbc7622488a25aba037ddbbd4a3f75675090039f6ee"),
        key: hex_literal!("d411d75fdc6db9ec1c88a9ca3b24b1cb7bb47616983b889844a9577187902592"),
    },
    Key {
        ver: hex_literal!("65570055b61bb9e44d53fff523faec85326404f13b2fe82b526db3fa6db0181d"),
        key: hex_literal!("79c873fb9f4c3d96bfb55a935725982f62ba9d1ef1c02d2a8983ad1b8f2b65fb"),
    },
    Key {
        ver: hex_literal!("23e9740c830664a7dffcf3eaa584f7da67f87ccb3506eccce3e31ea65d85432e"),
        key: hex_literal!("a165087e70a3da72d0c716d4e27dd4db01c7712dbcef8a4b0618e3c217b30736"),
    },
    Key {
        ver: hex_literal!("d9ff9773cb64f3d11c334b944e82249d4361ebec1838b400259ca35f59241e4f"),
        key: hex_literal!("7b40ff8e04ff9cbcbf0f73d312665cc6460e633486b346b828849e8b0f89f7d1"),
    },
    Key {
        ver: hex_literal!("adaf3204b24abcf52f8e472218fa11c8cbfc058ab5b75d720c3c05e42621a559"),
        key: hex_literal!("6823d01ae3fedd37c234986c150738155f3aa9b5b6bf4490e3900aa6efe4b70b"),
    },
    Key {
        ver: hex_literal!("73d8279b5085617610c937e9cdedf5930ea2451c2a0250a8cf8afc2ff773a63d"),
        key: hex_literal!("effd67a1a9f37e3cdf6041783092efec5a46ca30824f9065a4337713ff60a899"),
    },
    Key {
        ver: hex_literal!("4049fcba2d6da6c9991423d6039e6b4c5bcea1e9e1bc3476a1480cc73ea1d3c7"),
        key: hex_literal!("c4b652d110805a33115f5fbefdfeebc9202659c70d929324ffdc1df6cc9f4be4"),
    },
    Key {
        ver: hex_literal!("cf27fd2666da6accda99b438b6e27004bdd2ca72a8f8d364c49a9f13b280cb6c"),
        key: hex_literal!("69916348f93a5bfa3ec1e110fe16b4a9b595411c79ba77f03fbb39f3f9b7298c"),
    },
    Key {
        ver: hex_literal!("a09e5695da534bec0d88d4388bcc08872e067709aef023616b56f5f42d5d52a8"),
        key: hex_literal!("99824b071b481bb49028638afd54fab7321102bf93bfd5e52b3da62f7680ea40"),
    },
    Key {
        ver: hex_literal!("7603996761fda510e36c04557d21327592a5b54794794c3e74e0a2075d198180"),
        key: hex_literal!("008e9b91e1231555216d97230a05f0ba561bcf9404ce8f3aef2dff487c1d93a0"),
    },
    Key {
        ver: hex_literal!("20d0974af1b09ecd28fbe440afe73bc2f9671271f8372431cb34dbddf5511ad2"),
        key: hex_literal!("f38b609edb012dcbc4b32e4566118685ddc188cf68dd122b46a80ec78ab1662f"),
    },
    Key {
        ver: hex_literal!("de8d77b77b058c33fe3a8ad84cb7e4c207b9110b47e4210109aa3073b12cc3ff"),
        key: hex_literal!("d96a3efd5096db42345fd988037fb19986cd19db5ec8d878684cac56b88c64b7"),
    },
    Key {
        ver: hex_literal!("573dc6f3b790a62c00f1a9425a9e3fd04b6f27f34fc190fa3a2353657f24caf0"),
        key: hex_literal!("69b6595eeaa5a249816fd0b34adb0ea38a413fa9f781b6eb0d13967bf904e953"),
    },
    Key {
        ver: hex_literal!("307bd2e1a01f86260c14f8ac0bf1b8af6deb852ca62a0c1151cca407721a0904"),
        key: hex_literal!("405bb1387f7a19d5c724fe9c708f098c3d39187ca9d5a49102e9e1c9c0ccdb7a"),
    },
    Key {
        ver: hex_literal!("04ba63b7b3f8e30328f192ec04d240862ea09c01619f551ed025cb9b4edaf1ac"),
        key: hex_literal!("b07e16a4c801a85fad2d4320b174391ab1bc4beda163616259794e6709884ee2"),
    },
    Key {
        ver: hex_literal!("ea1a9c3db4e2863f92d89c8598fd6e1682cf7833942b9862eb76dfce1a169796"),
        key: hex_literal!("c5d3a6bbf1bfab44bc27ead9bc8cdc4507b526c2f3ad9c685197d0838fa871af"),
    },
];
