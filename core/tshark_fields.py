"""Helpers for robust ``tshark -T fields`` parsing."""

from __future__ import annotations

import csv
import io
from typing import List, Optional

# ASCII Unit Separator. It is far less likely to appear in HTTP payloads,
# URIs, headers, or decoded text than pipe, comma, or tab, and unlike 0x1e it
# is not treated as a line boundary by Python's str.splitlines().
FIELD_SEPARATOR = "\x1f"


def separator_arg() -> str:
    return f"separator={FIELD_SEPARATOR}"


def split_fields(line: str, expected: Optional[int] = None) -> List[str]:
    """Split a tshark fields line using the project-wide safe separator."""
    if not line:
        return []
    fields = line.rstrip("\r\n").split(FIELD_SEPARATOR)
    if expected is not None and len(fields) < expected:
        return fields + [""] * (expected - len(fields))
    return fields


def parse_quoted_fields(line: str, expected: Optional[int] = None) -> List[str]:
    """Parse fields output when tshark is called with ``-E quote=d``."""
    if not line:
        return []
    reader = csv.reader(io.StringIO(line), delimiter=FIELD_SEPARATOR, quotechar='"')
    try:
        fields = next(reader)
    except StopIteration:
        fields = []
    if expected is not None and len(fields) < expected:
        return fields + [""] * (expected - len(fields))
    return fields
