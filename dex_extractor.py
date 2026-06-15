"""
DEX string pool extractor — pure Python, no external dependencies.

Parses the Dalvik Executable (DEX) binary format and extracts content
strings (Level 2 data). Filters out Java internals, class descriptors,
and machine-generated identifiers, keeping only natural-language text.
"""

import re
import struct
from pathlib import Path


# ── Public API ─────────────────────────────────────────────────────────────────

def extract_content_strings(dex_path) -> list:
    """
    Parse one DEX file and return a list of content-like strings.
    Returns [] on any error (bad magic, truncated file, etc.).
    """
    try:
        data = Path(dex_path).read_bytes()
    except Exception:
        return []

    # Validate DEX magic: "dex\n035\0" or "dex\n036\0" etc.
    if data[:4] != b'dex\n':
        return []

    try:
        string_ids_size = struct.unpack_from('<I', data, 56)[0]
        string_ids_off  = struct.unpack_from('<I', data, 60)[0]
    except struct.error:
        return []

    if string_ids_size == 0 or string_ids_off == 0:
        return []

    results = []
    for i in range(string_ids_size):
        try:
            str_off = struct.unpack_from('<I', data, string_ids_off + i * 4)[0]
            length, pos = _read_uleb128(data, str_off)
            if length == 0 or length > 4096:
                continue
            raw = data[pos: pos + length]
            s = raw.decode('utf-8', errors='replace')
            if _is_content(s):
                results.append(s)
        except Exception:
            continue

    return results


def build_chapter_json(strings: list) -> tuple:
    """
    Convert a flat list of content strings into Flutter-compatible JSON.

    Returns (contains_dict, chapter1_dict) ready to be written as:
      assets/database/contains.json
      assets/database/chapter1.json
    """
    items = [
        {
            "id":     str(i + 1),
            "shlok":  _clean(s),
            "exp_hi": "",
            "exp_mr": "",
            "exp_en": "",
        }
        for i, s in enumerate(strings)
        if _clean(s)   # skip items that become empty after cleaning
    ]
    contains = {"items": [{"id": 1, "subtitle": "Extracted Content"}]}
    chapter  = {"items": items}
    return contains, chapter


def _clean(s: str) -> str:
    """
    Strip formatting artefacts from DEX-extracted strings.
    - Remove leading/trailing whitespace and blank lines
    - Collapse runs of 3+ newlines → double newline (paragraph break)
    - Remove lines that are only whitespace
    - Normalize half-width katakana space (U+FFA0) used as padding in some APKs
    """
    s = s.replace('ﾠ', ' ')           # half-width katakana space → regular space
    s = re.sub(r'\r\n?', '\n', s)          # CRLF → LF
    lines = [ln.rstrip() for ln in s.split('\n')]
    s = '\n'.join(lines)
    s = re.sub(r'\n{3,}', '\n\n', s)       # 3+ blank lines → paragraph break
    s = s.strip()
    return s


# ── DEX binary helpers ─────────────────────────────────────────────────────────

def _read_uleb128(data: bytes, offset: int):
    """Read ULEB128 integer. Returns (value, new_offset)."""
    result, shift = 0, 0
    while True:
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, offset
        shift += 7


# ── Content-string filter ──────────────────────────────────────────────────────

# Patterns that identify Java / Dalvik internals — definitely NOT content
_JAVA_TYPE  = re.compile(r'^[LB\[Z\(]')         # type descriptors: Lcom/Foo; [I
_JAVA_PKG   = re.compile(r'^[a-z]{2,}\.[a-z]')  # fully-qualified: com.android, java.lang
_HEX_UUID   = re.compile(r'^[0-9a-fA-F\-]{20,}$')
_URL        = re.compile(r'^https?://')
_FILE_PATH  = re.compile(r'^[/\\]|\.xml$|\.png$|\.class$|\.so$')
_SQL_STMT   = re.compile(
    r'^(CREATE\s+TABLE|INSERT\s+(OR\s+\w+\s+)?INTO|ALTER\s+TABLE|SELECT\s|DROP\s+TABLE|UPDATE\s)',
    re.IGNORECASE,
)


def _is_content(s: str) -> bool:
    """Return True if the string looks like actual human-readable content."""
    if len(s) < 15:
        return False

    # Skip Java / system internals
    if _JAVA_TYPE.match(s):
        return False
    if _JAVA_PKG.match(s):
        return False
    if _HEX_UUID.match(s):
        return False
    if _URL.match(s):
        return False
    if _FILE_PATH.search(s):
        return False
    if _SQL_STMT.match(s):
        return False

    # Skip strings that contain many non-printable bytes (binary blobs)
    control_chars = sum(1 for c in s if ord(c) < 32 and c not in '\n\t\r')
    if control_chars > 3:
        return False

    # Slash-heavy paths (res/drawable/icon.png)
    if s.count('/') > 2:
        return False

    # Contains non-ASCII (Devanagari, Sanskrit, regional script) — keep
    if any(ord(c) > 127 for c in s):
        # But not if it's mostly replacement chars (UTF-8 decode errors)
        bad = s.count('�')
        if bad > len(s) * 0.2:
            return False
        return True

    # Looks like a natural-language sentence: 4+ words, starts with capital
    words = s.split()
    if len(words) >= 4 and s[0].isupper():
        return True

    return False
