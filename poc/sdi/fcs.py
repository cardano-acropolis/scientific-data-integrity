"""A minimal, dependency-free FCS 3.0/3.1 reader.

Enough of the Flow Cytometry Standard to (1) separate the TEXT (metadata)
segment from the DATA (event) segment so their hashes are independent, and
(2) split DATA into per-event rows for the Merkle tree. This is deliberately
small; it is not a full FCS implementation (no supplemental TEXT, no CRC, no
double-delimiter escaping beyond the common case).

FCS layout:
  HEADER  58 bytes: 6-byte version, 4 spaces, then six 8-byte ASCII ints giving
          the byte offsets of TEXT/DATA/ANALYSIS (start, end; end is inclusive).
  TEXT    first byte is the delimiter; then delimiter-separated key/value pairs.
  DATA    packed events; row width derives from $PAR, $DATATYPE and $PnB.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class FCS:
    version: str
    keywords: dict[str, str]
    text_bytes: bytes
    data_bytes: bytes
    event_rows: list[bytes] = field(default_factory=list)
    row_method: str = "unknown"  # "per-event-row" or "fixed-chunk-fallback"

    @property
    def par(self) -> int:
        return int(self.keywords.get("$PAR", "0") or "0")

    @property
    def tot(self) -> int:
        return int(self.keywords.get("$TOT", "0") or "0")


def _header_int(raw: bytes, start: int, end: int) -> int:
    token = raw[start:end].decode("ascii", "replace").strip()
    return int(token) if token else 0


def _row_width_bytes(keywords: dict[str, str]) -> int | None:
    """Bytes per event row, or None if it can't be determined confidently."""
    par = int(keywords.get("$PAR", "0") or "0")
    if par <= 0:
        return None
    datatype = keywords.get("$DATATYPE", "").upper()
    if datatype == "F":
        return par * 4
    if datatype == "D":
        return par * 8
    if datatype == "I":
        total = 0
        for i in range(1, par + 1):
            bits = keywords.get(f"$P{i}B")
            if bits is None or not bits.isdigit() or int(bits) % 8:
                return None
            total += int(bits) // 8
        return total
    return None


def parse(raw: bytes) -> FCS:
    version = raw[0:6].decode("ascii", "replace")
    text_start = _header_int(raw, 10, 18)
    text_end = _header_int(raw, 18, 26)
    data_start = _header_int(raw, 26, 34)
    data_end = _header_int(raw, 34, 42)

    delim = raw[text_start : text_start + 1]
    text_bytes = raw[text_start : text_end + 1]
    body = raw[text_start + 1 : text_end + 1]
    tokens = body.split(delim)
    if tokens and tokens[-1] == b"":
        tokens = tokens[:-1]
    keywords = {
        tokens[i].decode("latin1").strip(): tokens[i + 1].decode("latin1")
        for i in range(0, len(tokens) - 1, 2)
    }

    # Large/segmented files put real DATA offsets in TEXT, not the header.
    if data_start == 0 and "$BEGINDATA" in keywords:
        data_start = int(keywords["$BEGINDATA"])
        data_end = int(keywords["$ENDDATA"])
    data_bytes = raw[data_start : data_end + 1] if data_end >= data_start else b""

    fcs = FCS(version=version, keywords=keywords, text_bytes=text_bytes, data_bytes=data_bytes)

    width = _row_width_bytes(keywords)
    tot = fcs.tot
    if width and tot and len(data_bytes) == width * tot:
        fcs.event_rows = [data_bytes[i * width : (i + 1) * width] for i in range(tot)]
        fcs.row_method = "per-event-row"
    else:
        fcs.event_rows = []  # caller falls back to fixed-size chunking
        fcs.row_method = "fixed-chunk-fallback"
    return fcs


# MIFlowCyt-relevant keywords worth surfacing in the manifest.
MIFLOWCYT_KEYS = (
    "$CYT", "$CYTSN", "$DATE", "$BTIM", "$ETIM", "$OP", "$SRC",
    "$INST", "$SYS", "$PAR", "$TOT", "$DATATYPE", "$MODE", "$BYTEORD",
)


def build_fcs_3_1(
    *,
    params: list[str],
    events: list[list[float]],
    extra_keywords: dict[str, str] | None = None,
) -> bytes:
    """Build a minimal valid FCS 3.1 file (float32 data) for testing/demos."""
    import struct

    par = len(params)
    tot = len(events)
    delim = b"/"

    kw: dict[str, str] = {
        "$BEGINANALYSIS": "0", "$ENDANALYSIS": "0",
        "$BYTEORD": "1,2,3,4", "$DATATYPE": "F", "$MODE": "L",
        "$NEXTDATA": "0", "$PAR": str(par), "$TOT": str(tot),
    }
    for i, name in enumerate(params, start=1):
        kw[f"$P{i}N"] = name
        kw[f"$P{i}B"] = "32"
        kw[f"$P{i}E"] = "0,0"
        kw[f"$P{i}R"] = "262144"
    if extra_keywords:
        kw.update(extra_keywords)

    data = b"".join(struct.pack("<f", v) for row in events for v in row)

    header_len = 58  # 6-byte version + 4 spaces + six fixed 8-byte offset fields
    text_start = header_len

    def render(begindata: int, enddata: int) -> bytes:
        k = dict(kw, **{"$BEGINDATA": str(begindata), "$ENDDATA": str(enddata)})
        body = bytearray(delim)
        for key, val in k.items():
            body += key.encode("latin1") + delim + val.encode("latin1") + delim
        return bytes(body)

    # TEXT length depends on the digit counts of the DATA offsets it contains,
    # so iterate to a fixed point.
    data_start = data_end = 0
    for _ in range(6):
        text = render(data_start, data_end)
        text_end = text_start + len(text) - 1
        new_start = text_end + 1
        new_end = new_start + len(data) - 1
        if (new_start, new_end) == (data_start, data_end):
            break
        data_start, data_end = new_start, new_end

    if any(v > 99_999_999 for v in (text_end, data_start, data_end)):
        raise RuntimeError("offsets exceed 8-digit header fields; use $BEGINDATA")

    def pad(n: int) -> bytes:
        return str(n).rjust(8).encode("ascii")

    header = (
        b"FCS3.1" + b" " * 4
        + pad(text_start) + pad(text_end)
        + pad(data_start) + pad(data_end)
        + pad(0) + pad(0)
    )
    assert len(header) == header_len, len(header)
    return header + text + data
