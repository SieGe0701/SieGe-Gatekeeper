from __future__ import annotations

import re
from typing import Iterable

from app.diff_parser import FileDiff

from . import Finding

EVAL_RE = re.compile(r"\beval\s*\(")
EXEC_RE = re.compile(r"\bexec\s*\(")
SUBPROCESS_SHELL_RE = re.compile(r"\bsubprocess\.\w+\(.*shell\s*=\s*True")
PICKLE_LOAD_RE = re.compile(r"\bpickle\.loads?\(")
YAML_LOAD_RE = re.compile(r"\byaml\.load\s*\(")


def python_security_findings(file_diffs: Iterable[FileDiff]) -> list[Finding]:
    findings: list[Finding] = []
    for file_diff in file_diffs:
        if file_diff.language != "python":
            continue

        for changed_line in file_diff.changed_lines:
            text = changed_line.content
            snippet = (text.strip() or "<empty line>")[:160]

            if EVAL_RE.search(text):
                findings.append(
                    Finding(
                        path=file_diff.path,
                        line=changed_line.number,
                        severity="high",
                        rule_id="PY_EVAL_USAGE",
                        message="Avoid `eval()` on changed lines; use safer parsing.",
                        snippet=snippet,
                    )
                )

            if EXEC_RE.search(text):
                findings.append(
                    Finding(
                        path=file_diff.path,
                        line=changed_line.number,
                        severity="high",
                        rule_id="PY_EXEC_USAGE",
                        message="Avoid `exec()` on changed lines.",
                        snippet=snippet,
                    )
                )

            if SUBPROCESS_SHELL_RE.search(text):
                findings.append(
                    Finding(
                        path=file_diff.path,
                        line=changed_line.number,
                        severity="high",
                        rule_id="PY_SUBPROCESS_SHELL_TRUE",
                        message=(
                            "subprocess with shell=True on changed line may enable "
                            "command injection."
                        ),
                        snippet=snippet,
                    )
                )

            if PICKLE_LOAD_RE.search(text):
                findings.append(
                    Finding(
                        path=file_diff.path,
                        line=changed_line.number,
                        severity="medium",
                        rule_id="PY_PICKLE_LOAD",
                        message=(
                            "pickle.loads/load can execute arbitrary code on untrusted "
                            "input."
                        ),
                        snippet=snippet,
                    )
                )

            if YAML_LOAD_RE.search(text) and "safe_load" not in text:
                findings.append(
                    Finding(
                        path=file_diff.path,
                        line=changed_line.number,
                        severity="medium",
                        rule_id="PY_YAML_LOAD",
                        message="Use yaml.safe_load instead of yaml.load.",
                        snippet=snippet,
                    )
                )

    return findings
