use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Text(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn text<S: Into<String>>(s: S) -> Value {
        Value::Text(s.into())
    }

    pub fn object(pairs: Vec<(&str, Value)>) -> Value {
        let mut map = BTreeMap::new();
        for (k, v) in pairs {
            map.insert(k.to_string(), v);
        }
        Value::Object(map)
    }
}
