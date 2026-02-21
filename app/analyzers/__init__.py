from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal

from app.diff_parser import FileDiff

Severity = Literal["high", "medium", "low"]
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    severity: Severity
    rule_id: str
    message: str
    snippet: str


def run_all_analyzers(file_diffs: Iterable[FileDiff]) -> list[Finding]:
    file_diffs_list = list(file_diffs)
    findings: list[Finding] = []

    from .complexity import complexity_findings
    from .lint import lint_findings
    from .python_ast import python_security_findings

    findings.extend(lint_findings(file_diffs_list))
    findings.extend(python_security_findings(file_diffs_list))
    findings.extend(complexity_findings(file_diffs_list))

    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_RANK.get(finding.severity, 99),
            finding.path,
            finding.line,
            finding.rule_id,
        ),
    )
