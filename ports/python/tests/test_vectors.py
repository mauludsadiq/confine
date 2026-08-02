import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from confine_core import encode, sha256_text, hmac_sha256, tagged_digest, certificate_mac_v1_fard


def test_confirmed_vector_primitive_sha256_001():
    assert sha256_text("hello") == "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_confirmed_vector_primitive_hmac_sha256_001():
    assert hmac_sha256("0123456789abcdef0123456789abcdef", "hello") == "1a0927a7ed7a365b7aa0eb128475351ad288913644d26507f115accac23aa5d6"


def test_confirmed_vector_tagged_action_digest_001():
    action = {
        "t": "read_invoice",
        "invoice_id": "inv_001",
        "nonce": "nonce-test-0001",
        "expected_state_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    }
    expected_canonical = '{"expected_state_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","invoice_id":"inv_001","nonce":"nonce-test-0001","t":"read_invoice"}'
    assert encode(action) == expected_canonical
    assert tagged_digest("confine.action.v2", action) == "sha256:9e0142a379294ab42e2e99768b8ceec99a96013526901d2ed977ccbcd5776d4c"


def test_confirmed_vector_v1_fard_certificate_mac():
    unsigned = {
        "t": "transition_certificate",
        "version": 1,
        "prior_state_hash": "sha256:20db1ed809ccec07704888c74ebae6d0ca9ee17119f6d46e03e2e0de88fa1576",
        "action_hash": "sha256:0f8f51e930266bf997e01135ba2b03a045d4779613ef04115c124319c6647281",
        "actor_id": "drafter_1",
        "policy_hash": "sha256:64d54739cc1ce345d4f9ad87efdcf818612de708830ab2c9ed9847c0b9eb7c5e",
        "capability_hash": "sha256:07ffa73a9a69e9d9dcd9850a8d6ed5cdbc4dfff13b7fdbdb880612fa1283ffcb",
        "nonce": "nonce-test-0001",
        "sequence": 0,
        "obligations": [
            {
                "t": "result_label",
                "label": {
                    "kind": "customer",
                    "owner": "cust_001",
                    "compartments": ["customer_data"],
                },
            }
        ],
    }
    secret = "0123456789abcdef0123456789abcdef"
    assert certificate_mac_v1_fard(secret, unsigned) == "sha256:82957e569924a2ea7a68495e9cbe7081e36a9b71ac439af9fc23f644763b4a54"
