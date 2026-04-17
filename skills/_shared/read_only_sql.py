"""Shared validation for read-only warehouse source queries."""

from __future__ import annotations

import re

ALLOWED_PREFIXES = ("SELECT", "WITH", "SHOW", "DESCRIBE")
DISALLOWED_PATTERNS = (
    re.compile(r"--"),
    re.compile(r"/\*"),
    re.compile(r"\*/"),
    re.compile(
        r"\b(?:"
        r"ALTER|ANALYZE|CACHE|CALL|COPY\s+INTO|CREATE|DELETE|DROP|EXECUTE\s+IMMEDIATE|"
        r"GET|GRANT|INSERT|MERGE|MSCK|OPTIMIZE|PUT|REFRESH|REPAIR|REVOKE|SET|TRUNCATE|"
        r"UNCACHE|UNDROP|UNSET|UPDATE|USE|VACUUM"
        r")\b"
    ),
    re.compile(r"\bIDENTIFIER\s*\("),
    re.compile(r"\bSYSTEM\$"),
)


def normalize_read_only_query(query: str) -> str:
    """Normalize and reject anything outside the repo's read-only SQL subset."""
    cleaned = query.strip()
    if not cleaned:
        raise ValueError("query must not be empty")
    while cleaned.endswith(";"):
        cleaned = cleaned[:-1].rstrip()
    if ";" in cleaned:
        raise ValueError("multiple SQL statements are not allowed")

    head = cleaned.lstrip("(\n\t ").upper()
    if not any(head.startswith(prefix) for prefix in ALLOWED_PREFIXES):
        raise ValueError("only SELECT, WITH, SHOW, and DESCRIBE statements are allowed")

    validate_read_only_shape(cleaned)
    return cleaned


def strip_quoted_sql(text: str) -> str:
    """Mask quoted content before keyword scanning so string literals stay allowed."""
    result: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(text):
        char = text[index]
        if quote is None and char in ("'", '"', "`"):
            quote = char
            result.append(" ")
            index += 1
            continue
        if quote is not None:
            if char == quote:
                if index + 1 < len(text) and text[index + 1] == quote:
                    index += 2
                    continue
                quote = None
            result.append(" ")
            index += 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


def validate_read_only_shape(query: str) -> None:
    stripped = strip_quoted_sql(query).upper()
    validate_balanced_parentheses(stripped)
    for pattern in DISALLOWED_PATTERNS:
        if pattern.search(stripped):
            raise ValueError(
                "query contains comments, session controls, or write-oriented keywords; "
                "only plain read-only SELECT, WITH, SHOW, and DESCRIBE queries are allowed"
            )


def validate_balanced_parentheses(text: str) -> None:
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise ValueError("query has unbalanced parentheses")
    if depth != 0:
        raise ValueError("query has unbalanced parentheses")
