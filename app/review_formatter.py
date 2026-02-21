from __future__ import annotations

import os
from collections import Counter
from typing import Iterable

from app.analyzers import Finding
from app.diff_parser import FileDiff


def build_review_payload(
    findings: Iterable[Finding],
    file_diffs: Iterable[FileDiff],
) -> tuple[str, list[dict[str, object]]]:
    findings_list = list(findings)
    diffs_list = list(file_diffs)
    changed_lines_count = sum(len(file_diff.changed_lines) for file_diff in diffs_list)

    max_inline_comments = _env_int("MAX_INLINE_COMMENTS", 50)

    if not findings_list:
        body = (
            "## SieGe Gatekeeper Review\n\n"
            "### Scope\n"
            f"- Files analyzed: {len(diffs_list)}\n"
            f"- Changed lines analyzed: {changed_lines_count}\n\n"
            "### Result\n"
            "No issues found on changed lines."
        )
        return body, []

    severity_counts = Counter(finding.severity for finding in findings_list)
    body_lines: list[str] = [
        "## SieGe Gatekeeper Review",
        "",
        "### Scope",
        f"- Files analyzed: {len(diffs_list)}",
        f"- Changed lines analyzed: {changed_lines_count}",
        f"- Findings: {len(findings_list)}",
        "",
        "### Severity Breakdown",
        "| Severity | Count |",
        "| --- | ---: |",
        f"| HIGH | {severity_counts.get('high', 0)} |",
        f"| MEDIUM | {severity_counts.get('medium', 0)} |",
        f"| LOW | {severity_counts.get('low', 0)} |",
        "",
        "### Findings (Changed Lines Only)",
        "| File | Line | Severity | Rule | Message |",
        "| --- | ---: | --- | --- | --- |",
    ]

    max_table_rows = 40
    for finding in findings_list[:max_table_rows]:
        body_lines.append(
            "| "
            f"`{_escape_cell(finding.path)}` | "
            f"{finding.line} | "
            f"{finding.severity.upper()} | "
            f"`{_escape_cell(finding.rule_id)}` | "
            f"{_escape_cell(finding.message)} |"
        )

    if len(findings_list) > max_table_rows:
        body_lines.extend(
            [
                "",
                (
                    f"_Table truncated to first {max_table_rows} findings; "
                    f"{len(findings_list) - max_table_rows} additional finding(s) "
                    "included in summary only._"
                ),
            ]
        )

    inline_comments = _build_inline_comments(findings_list, limit=max_inline_comments)
    if len(findings_list) > len(inline_comments):
        body_lines.extend(
            [
                "",
                (
                    f"_Inline comments limited to {len(inline_comments)} lines "
                    f"(config `MAX_INLINE_COMMENTS={max_inline_comments}`)._"
                ),
            ]
        )

    return "\n".join(body_lines), inline_comments


def _build_inline_comments(
    findings: list[Finding], limit: int
) -> list[dict[str, object]]:
    if limit <= 0:
        return []

    comments: list[dict[str, object]] = []
    seen: set[tuple[str, int, str]] = set()

    for finding in findings:
        unique_key = (finding.path, finding.line, finding.rule_id)
        if unique_key in seen:
            continue
        seen.add(unique_key)

        comment_body = (
            f"[{finding.severity.upper()}] {finding.message}\n\n"
            f"`{finding.snippet or '<empty line>'}`"
        )
        comments.append(
            {
                "path": finding.path,
                "line": finding.line,
                "side": "RIGHT",
                "body": comment_body[:64000],
            }
        )
        if len(comments) >= limit:
            break

    return comments


def _escape_cell(value: str) -> str:
    return value.replace("|", "\\|")


def _env_int(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    try:
        return int(raw_value)
    except ValueError:
        return default
