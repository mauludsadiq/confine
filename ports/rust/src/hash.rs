use crate::canonical::encode;
use crate::value::Value;
use sha2::{Digest, Sha256};
use hmac::{Hmac, Mac};

pub fn sha256_text(s: &str) -> String {
    let digest = Sha256::digest(s.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

pub fn tagged_digest(tag: &str, value: &Value) -> String {
    assert!(!tag.is_empty() && tag.is_ascii(), "tag must be non-empty ASCII");
    let mut preimage = Vec::new();
    preimage.extend_from_slice(tag.as_bytes());
    preimage.push(0x0a);
    preimage.extend_from_slice(encode(value).as_bytes());
    let digest = Sha256::digest(&preimage);
    format!("sha256:{}", hex::encode(digest))
}

pub fn hmac_sha256(key_hex_arg: &str, msg: &str) -> String {
    let key_bytes = hex::decode(key_hex_arg).expect("key_hex_arg must be valid hex");
    let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes).expect("HMAC can take key of any size");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn certificate_mac(key_hex_arg: &str, unsigned_cert: &Value) -> String {
    let key_bytes = hex::decode(key_hex_arg).expect("key_hex_arg must be valid hex");
    let mut mac = Hmac::<Sha256>::new_from_slice(&key_bytes).expect("HMAC can take key of any size");
    mac.update(b"confine.certificate.mac.v2");
    mac.update(&[0x0a]);
    mac.update(encode(unsigned_cert).as_bytes());
    format!("sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

// Matches packages/confine/certificate.fard exactly: broker_secret is an
// arbitrary caller string, normalized internally via
// bytes.to_hex(bytes.of_str(secret)) before being passed to hmac_sha256
// (which hex-decodes it again). Net effect: the actual HMAC key is the
// raw UTF-8 bytes of the secret STRING itself -- NOT hex::decode(secret).
// This is a v1-fard artifact (tag confine.certificate.mac.v1).
pub fn certificate_mac_v1_fard(secret: &str, unsigned_cert: &Value) -> String {
    let key_bytes = secret.as_bytes();
    let mut mac = Hmac::<Sha256>::new_from_slice(key_bytes).expect("HMAC can take key of any size");
    mac.update(b"confine.certificate.mac.v1");
    mac.update(&[0x0a]);
    mac.update(encode(unsigned_cert).as_bytes());
    format!("sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmed_vector_primitive_sha256_001() {
        assert_eq!(
            sha256_text("hello"),
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn confirmed_vector_primitive_hmac_sha256_001() {
        assert_eq!(
            hmac_sha256("0123456789abcdef0123456789abcdef", "hello"),
            "1a0927a7ed7a365b7aa0eb128475351ad288913644d26507f115accac23aa5d6"
        );
    }

    #[test]
    fn confirmed_vector_tagged_action_digest_001() {
        let action = Value::object(vec![
            ("t", Value::text("read_invoice")),
            ("invoice_id", Value::text("inv_001")),
            ("nonce", Value::text("nonce-test-0001")),
            ("expected_state_hash", Value::text("sha256:0000000000000000000000000000000000000000000000000000000000000000")),
        ]);
        assert_eq!(
            tagged_digest("confine.action.v2", &action),
            "sha256:9e0142a379294ab42e2e99768b8ceec99a96013526901d2ed977ccbcd5776d4c"
        );
    }

    #[test]
    fn confirmed_vector_v1_fard_certificate_mac() {
        // NOTE: this uses tag "confine.certificate.mac.v1" deliberately --
        // it matches what the real packages/confine/certificate.fard
        // currently emits (v1-fard artifact per PROTOCOL.md §16), not the
        // clean "v2" tag used elsewhere in this crate. This test validates
        // that canonicalization + HMAC logic cross-checks correctly against
        // real fardrun output; it does NOT establish a v2 certificate
        // vector. Re-capture a genuine v2 vector once certificate.fard is
        // migrated to v2 tags.
        let unsigned = Value::object(vec![
            ("t", Value::text("transition_certificate")),
            ("version", Value::Int(1)),
            ("prior_state_hash", Value::text("sha256:20db1ed809ccec07704888c74ebae6d0ca9ee17119f6d46e03e2e0de88fa1576")),
            ("action_hash", Value::text("sha256:0f8f51e930266bf997e01135ba2b03a045d4779613ef04115c124319c6647281")),
            ("actor_id", Value::text("drafter_1")),
            ("policy_hash", Value::text("sha256:64d54739cc1ce345d4f9ad87efdcf818612de708830ab2c9ed9847c0b9eb7c5e")),
            ("capability_hash", Value::text("sha256:07ffa73a9a69e9d9dcd9850a8d6ed5cdbc4dfff13b7fdbdb880612fa1283ffcb")),
            ("nonce", Value::text("nonce-test-0001")),
            ("sequence", Value::Int(0)),
            ("obligations", Value::Array(vec![
                Value::object(vec![
                    ("t", Value::text("result_label")),
                    ("label", Value::object(vec![
                        ("kind", Value::text("customer")),
                        ("owner", Value::text("cust_001")),
                        ("compartments", Value::Array(vec![Value::text("customer_data")])),
                    ])),
                ]),
            ])),
        ]);

        let secret = "0123456789abcdef0123456789abcdef";
        let computed = certificate_mac_v1_fard(secret, &unsigned);

        assert_eq!(computed, "sha256:82957e569924a2ea7a68495e9cbe7081e36a9b71ac439af9fc23f644763b4a54");
    }
}
