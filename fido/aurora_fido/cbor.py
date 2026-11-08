# SPDX-License-Identifier: MIT
"""The CBOR subset CTAP2 uses, with CTAP2 canonical encoding.

Encoding follows CTAP2 section 8 ("CTAP2 canonical CBOR"): shortest integer
and length forms, definite lengths only, map keys ordered by major type, then
encoded length, then bytes. Decoding is strict about what CTAP2 forbids
(indefinite lengths, tags, floats, undefined, duplicate map keys, invalid
UTF-8, trailing bytes, deep nesting) and lenient about non-shortest integer
heads, which some platforms send.
"""


class CBORError(ValueError):
    """Malformed or unsupported CBOR."""


class CBORTypeError(CBORError):
    """Well-formed CBOR of a type CTAP2 does not allow here."""


MAX_DEPTH = 8


def _head(major, n):
    if n < 0:
        raise CBORError("negative length")
    if n < 24:
        return bytes([major << 5 | n])
    if n < 0x100:
        return bytes([major << 5 | 24, n])
    if n < 0x10000:
        return bytes([major << 5 | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([major << 5 | 26]) + n.to_bytes(4, "big")
    if n < 1 << 64:
        return bytes([major << 5 | 27]) + n.to_bytes(8, "big")
    raise CBORError("integer out of range")


def _key_order(encoded_key):
    return (encoded_key[0] >> 5, len(encoded_key), encoded_key)


def encode(value):
    """Encode value (bool, None, int, bytes, str, list, tuple, dict)."""
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        b = bytes(value)
        return _head(2, len(b)) + b
    if isinstance(value, str):
        b = value.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(value, (list, tuple)):
        return _head(4, len(value)) + b"".join(encode(v) for v in value)
    if isinstance(value, dict):
        items = sorted(((encode(k), encode(v)) for k, v in value.items()),
                       key=lambda kv: _key_order(kv[0]))
        for a, b in zip(items, items[1:]):
            if a[0] == b[0]:
                raise CBORError("duplicate map key")
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise CBORError(f"cannot encode {type(value).__name__}")


def _read_arg(data, off, ai):
    if ai < 24:
        return ai, off
    if ai > 27:
        raise CBORError("indefinite length or reserved additional info")
    n = 1 << (ai - 24)
    if off + n > len(data):
        raise CBORError("truncated")
    return int.from_bytes(data[off:off + n], "big"), off + n


def _decode(data, off, depth):
    if depth <= 0:
        raise CBORError("nested too deep")
    if off >= len(data):
        raise CBORError("truncated")
    ib = data[off]
    off += 1
    major, ai = ib >> 5, ib & 0x1F
    if major == 7:
        if ai == 20:
            return False, off
        if ai == 21:
            return True, off
        if ai == 22:
            return None, off
        if ai > 27:
            raise CBORError("break or reserved simple value")
        raise CBORTypeError("float, undefined or simple value")
    arg, off = _read_arg(data, off, ai)
    if major == 0:
        return arg, off
    if major == 1:
        return -1 - arg, off
    if major in (2, 3):
        if off + arg > len(data):
            raise CBORError("truncated string")
        raw = bytes(data[off:off + arg])
        off += arg
        if major == 2:
            return raw, off
        try:
            return raw.decode("utf-8"), off
        except UnicodeDecodeError as e:
            raise CBORError("invalid UTF-8") from e
    if major == 4:
        if arg > len(data) - off:
            raise CBORError("array longer than input")
        out = []
        for _ in range(arg):
            v, off = _decode(data, off, depth - 1)
            out.append(v)
        return out, off
    if major == 5:
        if arg > (len(data) - off) // 2:
            raise CBORError("map longer than input")
        out = {}
        for _ in range(arg):
            k, off = _decode(data, off, depth - 1)
            if isinstance(k, (list, dict)):
                raise CBORTypeError("container as map key")
            v, off = _decode(data, off, depth - 1)
            # Python folds True into 1 as a key; such a map is refused too.
            if k in out:
                raise CBORError("duplicate map key")
            out[k] = v
        return out, off
    raise CBORTypeError("tagged value")


def decode(data, max_depth=MAX_DEPTH):
    """Decode exactly one CBOR item that fills data."""
    mv = memoryview(bytes(data))
    value, off = _decode(mv, 0, max_depth)
    if off != len(mv):
        raise CBORError("trailing bytes")
    return value


def decode_prefix(data, max_depth=MAX_DEPTH):
    """Decode one item from the start of data; return (value, rest)."""
    mv = memoryview(bytes(data))
    value, off = _decode(mv, 0, max_depth)
    return value, bytes(mv[off:])
