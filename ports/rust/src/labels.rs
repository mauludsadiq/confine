//! Label lattice and information-flow rules (spec PROTOCOL.md sec 7).
//!
//! Direct port of packages/confine/labels.fard. Verified against 12 real
//! flows_to() truth-table vectors captured from fardrun v1.7.0 -- see the
//! tests below. No behavior here is invented; every branch traces to a
//! specific line in labels.fard.

use crate::value::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub kind: String,
    pub owner: String,
    pub compartments: Vec<String>,
}

impl Label {
    pub fn public() -> Label {
        Label { kind: "public".into(), owner: "*".into(), compartments: vec![] }
    }
    pub fn internal() -> Label {
        Label { kind: "internal".into(), owner: "organization".into(), compartments: vec![] }
    }
    pub fn customer(customer_id: &str) -> Label {
        Label {
            kind: "customer".into(),
            owner: customer_id.into(),
            compartments: vec!["customer_data".into()],
        }
    }
    pub fn secret(secret_id: &str) -> Label {
        Label {
            kind: "secret".into(),
            owner: secret_id.into(),
            compartments: vec!["secret".into()],
        }
    }

    pub fn to_value(&self) -> Value {
        let mut map = BTreeMap::new();
        map.insert("kind".to_string(), Value::text(self.kind.clone()));
        map.insert("owner".to_string(), Value::text(self.owner.clone()));
        map.insert(
            "compartments".to_string(),
            Value::Array(self.compartments.iter().map(|c| Value::text(c.clone())).collect()),
        );
        Value::Object(map)
    }
}

fn rank(kind: &str) -> i32 {
    match kind {
        "public" => 0,
        "internal" => 1,
        "customer" => 2,
        "secret" => 3,
        _ => 100,
    }
}

fn valid(label: &Label) -> bool {
    rank(&label.kind) < 100
}

fn contains_all(xs: &[String], ys: &[String]) -> bool {
    ys.iter().all(|y| xs.contains(y))
}

/// Direct port of labels.fard's flows_to(). Branch order and logic match
/// the source exactly -- see PROTOCOL.md sec 7 for the formalized relation.
pub fn flows_to(source: &Label, sink: &Label) -> bool {
    if !valid(source) || !valid(sink) {
        return false;
    }
    match source.kind.as_str() {
        "public" => true,
        "internal" => rank(&sink.kind) >= 1,
        "customer" => {
            sink.kind == "customer"
                && source.owner == sink.owner
                && contains_all(&sink.compartments, &source.compartments)
        }
        "secret" => {
            sink.kind == "secret"
                && source.owner == sink.owner
                && contains_all(&sink.compartments, &source.compartments)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every value below was captured from a real fardrun v1.7.0 run
    // (examples/gen_label_vectors.fard) -- not derived from reading the
    // source alone. See conversation/commit history for the raw output.

    #[test]
    fn confirmed_flows_to_vectors() {
        let public = Label::public();
        let internal = Label::internal();
        let cust1 = Label::customer("cust_001");
        let cust2 = Label::customer("cust_002");
        let secret1 = Label::secret("s1");
        let secret2 = Label::secret("s2");

        assert_eq!(flows_to(&public, &internal), true);
        assert_eq!(flows_to(&public, &cust1), true);
        assert_eq!(flows_to(&internal, &public), false);
        assert_eq!(flows_to(&internal, &internal), true);
        assert_eq!(flows_to(&internal, &cust1), true);
        assert_eq!(flows_to(&cust1, &cust1), true);
        assert_eq!(flows_to(&cust1, &cust2), false);
        assert_eq!(flows_to(&cust1, &internal), false);
        assert_eq!(flows_to(&cust1, &secret1), false);
        assert_eq!(flows_to(&secret1, &secret1), true);
        assert_eq!(flows_to(&secret1, &secret2), false);
        assert_eq!(flows_to(&secret1, &cust1), false);
    }
}
