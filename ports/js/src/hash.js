// Tagged hashing and HMAC constructions (spec PROTOCOL.md sec 4-5).

import { createHash, createHmac } from "node:crypto";
import { encode } from "./canonical.js";

export function sha256Text(s) {
  return "sha256:" + createHash("sha256").update(s, "utf-8").digest("hex");
}

export function taggedDigest(tag, value) {
  if (!tag || !/^[\x00-\x7F]+$/.test(tag)) {
    throw new Error("tag must be non-empty ASCII");
  }
  const preimage = Buffer.concat([
    Buffer.from(tag, "ascii"),
    Buffer.from([0x0a]),
    Buffer.from(encode(value), "utf-8"),
  ]);
  return "sha256:" + createHash("sha256").update(preimage).digest("hex");
}

// Primitive HMAC-SHA256: keyHexArg is hex-decoded to raw bytes.
export function hmacSha256(keyHexArg, msg) {
  const keyBytes = Buffer.from(keyHexArg, "hex");
  return createHmac("sha256", keyBytes).update(msg, "utf-8").digest("hex");
}

// Clean v2 construction: keyHexArg used directly as hex-decoded key.
export function certificateMac(keyHexArg, unsignedCert) {
  const keyBytes = Buffer.from(keyHexArg, "hex");
  const message = Buffer.concat([
    Buffer.from("confine.certificate.mac.v2\x0a", "ascii"),
    Buffer.from(encode(unsignedCert), "utf-8"),
  ]);
  return "sha256:" + createHmac("sha256", keyBytes).update(message).digest("hex");
}

// Matches packages/confine/certificate.fard exactly: broker_secret is an
// arbitrary caller string, normalized via bytes.to_hex(bytes.of_str(secret))
// before being passed to hmac_sha256 (which hex-decodes it again). Net
// effect: the actual HMAC key is the raw UTF-8 bytes of the secret
// STRING itself -- not Buffer.from(secret, "hex"). v1-fard artifact.
export function certificateMacV1Fard(secret, unsignedCert) {
  const keyBytes = Buffer.from(secret, "utf-8");
  const message = Buffer.concat([
    Buffer.from("confine.certificate.mac.v1\x0a", "ascii"),
    Buffer.from(encode(unsignedCert), "utf-8"),
  ]);
  return "sha256:" + createHmac("sha256", keyBytes).update(message).digest("hex");
}
