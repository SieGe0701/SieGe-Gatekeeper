from __future__ import annotations

import os
import re
from typing import Iterable

from app.diff_parser import FileDiff

from . import Finding

TODO_RE = re.compile(r"\b(TODO|FIXME|XXX)\b", flags=re.IGNORECASE)
MAX_LINE_LENGTH = int(os.getenv("MAX_LINE_LENGTH", "120"))


def lint_findings(file_diffs: Iterable[FileDiff]) -> list[Finding]:
    findings: list[Finding] = []
    for file_diff in file_diffs:
        for changed_line in file_diff.changed_lines:
            text = changed_line.content
            stripped = text.strip()
            snippet = (stripped or "<empty line>")[:160]

            if text.rstrip(" \t") != text:
                findings.append(
                    Finding(
                        path=file_diff.path,
                        line=changed_line.number,
                        severity="low",
                        rule_id="TRAILING_WHITESPACE",
                        message="Line has trailing whitespace.",
                        snippet=snippet,
                    )
                )

            if len(text) > MAX_LINE_LENGTH:
                findings.append(
                    Finding(
                        path=file_diff.path,
                        line=changed_line.number,
                        severity="low",
                        rule_id="LINE_TOO_LONG",
                        message=(
                            f"Line length is {len(text)} characters "
                            f"(limit: {MAX_LINE_LENGTH})."
                        ),
                        snippet=snippet,
                    )
                )

            if TODO_RE.search(text):
                findings.append(
                    Finding(
                        path=file_diff.path,
                        line=changed_line.number,
                        severity="low",
                        rule_id="TODO_COMMENT",
                        message="TODO/FIXME marker found in changed line.",
                        snippet=snippet,
                    )
                )

            if file_diff.language == "python":
                if stripped.startswith("print("):
                    findings.append(
                        Finding(
                            path=file_diff.path,
                            line=changed_line.number,
                            severity="low",
                            rule_id="PY_DEBUG_PRINT",
                            message=(
                                "Debug print statement found in changed line."
                            ),
                            snippet=snippet,
                        )
                    )

                indentation = text[: len(text) - len(text.lstrip(" \t"))]
                if "\t" in indentation:
                    findings.append(
                        Finding(
                            path=file_diff.path,
                            line=changed_line.number,
                            severity="medium",
                            rule_id="PY_TAB_INDENT",
                            message=(
                                "Tab character used for indentation in Python code."
                            ),
                            snippet=snippet,
                        )
                    )

            if file_diff.language in {"javascript", "typescript"}:
                if "console.log(" in stripped:
                    findings.append(
                        Finding(
                            path=file_diff.path,
                            line=changed_line.number,
                            severity="low",
                            rule_id="JS_DEBUG_LOG",
                            message=(
                                "Debug console.log statement found in changed line."
                            ),
                            snippet=snippet,
                        )
                    )

    return findings
