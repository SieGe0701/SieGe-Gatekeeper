from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Iterable

HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

LANGUAGE_BY_EXTENSION = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".kt": "kotlin",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".sh": "shell",
    ".sql": "sql",
    ".swift": "swift",
    ".ts": "typescript",
    ".tsx": "typescript",
}


@dataclass(frozen=True)
class ChangedLine:
    number: int
    content: str


@dataclass(frozen=True)
class FileDiff:
    path: str
    language: str
    additions: int
    deletions: int
    changed_lines: list[ChangedLine]


def detect_language(file_path: str) -> str:
    _, extension = os.path.splitext(file_path.lower())
    return LANGUAGE_BY_EXTENSION.get(extension, "text")


def parse_patch(patch: str) -> list[ChangedLine]:
    changed_lines: list[ChangedLine] = []
    new_line_number = 0

    for raw_line in patch.splitlines():
        if raw_line.startswith("@@"):
            match = HUNK_HEADER_RE.match(raw_line)
            if not match:
                continue
            new_line_number = int(match.group(1))
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            changed_lines.append(
                ChangedLine(number=new_line_number, content=raw_line[1:])
            )
            new_line_number += 1
            continue

        if raw_line.startswith("-") and not raw_line.startswith("---"):
            continue

        if raw_line.startswith("\\"):
            continue

        new_line_number += 1

    return changed_lines


def build_file_diffs(files_payload: Iterable[dict[str, Any]]) -> list[FileDiff]:
    diffs: list[FileDiff] = []
    for changed_file in files_payload:
        path = str(changed_file.get("filename", "")).strip()
        if not path:
            continue

        patch = changed_file.get("patch")
        if not patch:
            # Binary files and very large patches may not include a patch body.
            continue

        changed_lines = parse_patch(str(patch))
        if not changed_lines:
            continue

        diffs.append(
            FileDiff(
                path=path,
                language=detect_language(path),
                additions=int(changed_file.get("additions", 0) or 0),
                deletions=int(changed_file.get("deletions", 0) or 0),
                changed_lines=changed_lines,
            )
        )

    return diffs
