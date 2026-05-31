"""SQL helpers — used to escape LIKE wildcards from user input."""
from __future__ import annotations


# Use backslash as the escape char. SQLite's LIKE supports `ESCAPE '\\'`.
_LIKE_ESCAPE = "\\"


def like(pattern: str) -> str:
    """Escape SQL LIKE wildcards (`%`, `_`) and the escape char itself.

    Returns the *inner* pattern body — caller still has to wrap it with
    the wildcards they want (typically `%...%` for "contains") and append
    `ESCAPE '\\'` to the LIKE clause:

        WHERE title LIKE ? ESCAPE '\\\\'
        params = (f"%{like(q)}%",)
    """
    if not pattern:
        return ""
    return (
        pattern
        .replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2)
        .replace("%", _LIKE_ESCAPE + "%")
        .replace("_", _LIKE_ESCAPE + "_")
    )


# The literal `ESCAPE '\\'` suffix to append to a LIKE clause.
ESCAPE_CLAUSE = "ESCAPE '\\'"
