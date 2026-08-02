use crate::value::Value;

pub fn encode(v: &Value) -> String {
    let mut out = String::new();
    encode_into(v, &mut out);
    out
}

fn encode_into(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Text(s) => encode_string_into(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 { out.push(','); }
                encode_into(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, val)) in map.iter().enumerate() {
                if i > 0 { out.push(','); }
                encode_string_into(k, out);
                out.push(':');
                encode_into(val, out);
            }
            out.push('}');
        }
    }
}

fn encode_string_into(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmed_vector_tagged_action_digest_001_canonical_encoding() {
        let action = Value::object(vec![
            ("t", Value::text("read_invoice")),
            ("invoice_id", Value::text("inv_001")),
            ("nonce", Value::text("nonce-test-0001")),
            ("expected_state_hash", Value::text("sha256:0000000000000000000000000000000000000000000000000000000000000000")),
        ]);
        let expected = r#"{"expected_state_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","invoice_id":"inv_001","nonce":"nonce-test-0001","t":"read_invoice"}"#;
        assert_eq!(encode(&action), expected);
    }

    #[test]
    fn null_bool_int_encode_as_expected() {
        assert_eq!(encode(&Value::Null), "null");
        assert_eq!(encode(&Value::Bool(true)), "true");
        assert_eq!(encode(&Value::Bool(false)), "false");
        assert_eq!(encode(&Value::Int(42)), "42");
        assert_eq!(encode(&Value::Int(-42)), "-42");
        assert_eq!(encode(&Value::Int(0)), "0");
    }

    #[test]
    fn empty_object_and_array_encode_correctly() {
        assert_eq!(encode(&Value::object(vec![])), "{}");
        assert_eq!(encode(&Value::Array(vec![])), "[]");
    }
}
