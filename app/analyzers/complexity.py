from __future__ import annotations

import re
from typing import Iterable

from app.diff_parser import FileDiff

from . import Finding

MULTI_TERNARY_RE = re.compile(r"\?.*:.*\?.*:")


def complexity_findings(file_diffs: Iterable[FileDiff]) -> list[Finding]:
    findings: list[Finding] = []
    for file_diff in file_diffs:
        for changed_line in file_diff.changed_lines:
            text = changed_line.content
            stripped = text.strip()
            if not stripped:
                continue

            snippet = stripped[:160]
            logical_density = stripped.count(" and ") + stripped.count(" or ")
            if logical_density >= 3:
                findings.append(
                    Finding(
                        path=file_diff.path,
                        line=changed_line.number,
                        severity="medium",
                        rule_id="COMPLEX_BOOLEAN_EXPRESSION",
                        message=(
                            "Changed line has a dense boolean expression; "
                            "consider extracting named sub-expressions."
                        ),
                        snippet=snippet,
                    )
                )

            indentation_level = len(text) - len(text.lstrip(" "))
            if indentation_level >= 16 and stripped.startswith(
                ("if ", "for ", "while ", "try:", "with ")
            ):
                findings.append(
                    Finding(
                        path=file_diff.path,
                        line=changed_line.number,
                        severity="low",
                        rule_id="DEEP_NESTING",
                        message=(
                            "Changed control-flow line appears deeply nested; "
                            "consider refactoring."
                        ),
                        snippet=snippet,
                    )
                )

            if file_diff.language in {"javascript", "typescript"}:
                if MULTI_TERNARY_RE.search(stripped):
                    findings.append(
                        Finding(
                            path=file_diff.path,
                            line=changed_line.number,
                            severity="medium",
                            rule_id="NESTED_TERNARY",
                            message=(
                                "Nested ternary detected on changed line; "
                                "consider clearer control flow."
                            ),
                            snippet=snippet,
                        )
                    )

    return findings
