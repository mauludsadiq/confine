// Canonical UTF-8 encoding (spec PROTOCOL.md sec 3).
//
// Operates on native JS values: null, boolean, number (must be a safe
// integer -- see encode()), string, Array, and plain Object with string
// keys. No wrapper Value class. Object key order is explicitly sorted
// at encode time (by UTF-8 byte value), NOT relied upon from insertion
// order, since JS object key iteration order has historical quirks
// around integer-like keys that we do not want silently affecting the
// protocol's canonical bytes.

export function encode(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isInteger(v)) {
      throw new TypeError("floats are excluded from the restricted protocol value model (spec sec 2)");
    }
    if (!Number.isSafeInteger(v)) {
      throw new TypeError("integer outside safe range for this JS implementation");
    }
    return String(v);
  }
  if (typeof v === "string") return encodeString(v);
  if (Array.isArray(v)) {
    return "[" + v.map(encode).join(",") + "]";
  }
  if (typeof v === "object") {
    const keys = Object.keys(v).sort((a, b) => {
      const ba = Buffer.from(a, "utf-8");
      const bb = Buffer.from(b, "utf-8");
      return Buffer.compare(ba, bb);
    });
    const parts = keys.map((k) => encodeString(k) + ":" + encode(v[k]));
    return "{" + parts.join(",") + "}";
  }
  throw new TypeError(`value not in restricted protocol model: ${typeof v}`);
}

function encodeString(s) {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0);
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (ch === '\n') out += '\\n';
    else if (ch === '\t') out += '\\t';
    else if (ch === '\r') out += '\\r';
    else if (code < 0x20) out += '\\u' + code.toString(16).padStart(4, '0');
    else out += ch;
  }
  out += '"';
  return out;
}
