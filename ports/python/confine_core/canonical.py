"""Canonical UTF-8 encoding (spec PROTOCOL.md sec 3).

Operates directly on Python's native restricted-model types: None, bool,
int, str, list, dict[str, ...]. No wrapper Value class -- Python's dict
already supports string keys and arbitrary nesting, and we explicitly
sort keys at encode time rather than relying on insertion order, so any
dict construction order produces the same canonical bytes.
"""


def encode(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return _encode_string(v)
    if isinstance(v, list):
        return "[" + ",".join(encode(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v.keys(), key=lambda k: k.encode("utf-8"))
        parts = [_encode_string(k) + ":" + encode(v[k]) for k in keys]
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"value not in restricted protocol model: {type(v)}")


def _encode_string(s: str) -> str:
    out = ['"']
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '\r':
            out.append('\\r')
        elif ord(ch) < 0x20:
            out.append('\\u%04x' % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)
