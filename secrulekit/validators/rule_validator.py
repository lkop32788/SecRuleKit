"""Multi-format rule validator."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, List, Optional, Union

from secrulekit.parsers.yara_parser import YaraRule, YaraParser, YaraParseError
from secrulekit.parsers.sigma_parser import SigmaRule, SigmaParser, SigmaParseError
from secrulekit.parsers.suricata_parser import SuricataRule, SuricataParser, SuricataParseError


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class Finding:
    severity: Severity
    code: str
    message: str
    rule_name: Optional[str] = None
    file: Optional[Path] = None
    line: int = 0


@dataclass
class ValidationResult:
    findings: List[Finding] = field(default_factory=list)
    valid_count: int = 0
    error_count: int = 0
    warning_count: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)
        if finding.severity == Severity.ERROR:
            self.error_count += 1
        elif finding.severity == Severity.WARNING:
            self.warning_count += 1

    @property
    def passed(self) -> bool:
        return self.error_count == 0

    def summary(self) -> str:
        total = self.valid_count + self.error_count
        return (
            f"{self.valid_count}/{total} rules valid, "
            f"{self.error_count} errors, {self.warning_count} warnings"
        )


class RuleValidator:
    """Validate YARA, Sigma, and Suricata rules."""

    def __init__(self, strict: bool = False):
        self.strict = strict

    # ------------------------------------------------------------------ #
    #  YARA
    # ------------------------------------------------------------------ #

    def validate_yara(self, rule: YaraRule) -> List[Finding]:
        findings: List[Finding] = []

        if not rule.condition:
            findings.append(Finding(
                Severity.ERROR, "YARA001",
                "Rule has no condition block",
                rule_name=rule.name, file=rule.source_file, line=rule.line_number,
            ))

        if not rule.strings and "filesize" not in rule.condition and "all" not in rule.condition:
            findings.append(Finding(
                Severity.WARNING, "YARA002",
                "Rule has no strings and condition may never match",
                rule_name=rule.name, file=rule.source_file, line=rule.line_number,
            ))

        # Warn about overly broad conditions
        if rule.condition.strip() in ("true", "any of them"):
            findings.append(Finding(
                Severity.WARNING, "YARA003",
                f"Overly broad condition: '{rule.condition.strip()}'",
                rule_name=rule.name, file=rule.source_file, line=rule.line_number,
            ))

        # Check for potentially slow regex strings (no anchoring hint)
        for s in rule.strings:
            if s.type == "regex" and not s.value.startswith("/^"):
                findings.append(Finding(
                    Severity.INFO, "YARA004",
                    f"Unanchored regex string '{s.name}' may be slow on large files",
                    rule_name=rule.name, file=rule.source_file, line=rule.line_number,
                ))

        # Missing recommended meta fields
        for meta_key in ("description", "author"):
            if meta_key not in rule.meta:
                findings.append(Finding(
                    Severity.WARNING if self.strict else Severity.INFO,
                    "YARA005",
                    f"Missing recommended meta field: {meta_key}",
                    rule_name=rule.name, file=rule.source_file, line=rule.line_number,
                ))

        return findings

    # ------------------------------------------------------------------ #
    #  Sigma
    # ------------------------------------------------------------------ #

    def validate_sigma(self, rule: SigmaRule) -> List[Finding]:
        findings: List[Finding] = []

        if not rule.logsource:
            findings.append(Finding(
                Severity.ERROR, "SIGMA001",
                "Missing logsource block",
                rule_name=rule.title, file=rule.source_file,
            ))

        if not rule.detection:
            findings.append(Finding(
                Severity.ERROR, "SIGMA002",
                "Missing detection block",
                rule_name=rule.title, file=rule.source_file,
            ))

        if "condition" not in rule.detection:
            findings.append(Finding(
                Severity.ERROR, "SIGMA003",
                "detection block has no condition field",
                rule_name=rule.title, file=rule.source_file,
            ))

        if rule.level not in (None, "informational", "low", "medium", "high", "critical"):
            findings.append(Finding(
                Severity.WARNING, "SIGMA004",
                f"Unknown severity level: '{rule.level}'",
                rule_name=rule.title, file=rule.source_file,
            ))

        if not rule.id:
            findings.append(Finding(
                Severity.WARNING if self.strict else Severity.INFO,
                "SIGMA005",
                "Rule has no UUID id field",
                rule_name=rule.title, file=rule.source_file,
            ))

        return findings

    # ------------------------------------------------------------------ #
    #  Suricata
    # ------------------------------------------------------------------ #

    def validate_suricata(self, rule: SuricataRule) -> List[Finding]:
        findings: List[Finding] = []

        if not rule.sid:
            findings.append(Finding(
                Severity.ERROR, "SURI001",
                "Rule has no sid option",
                file=rule.source_file, line=rule.line_number,
            ))

        if not rule.msg:
            findings.append(Finding(
                Severity.WARNING, "SURI002",
                "Rule has no msg option",
                file=rule.source_file, line=rule.line_number,
            ))

        if "rev" not in rule.options:
            findings.append(Finding(
                Severity.INFO, "SURI003",
                "Rule has no rev option",
                file=rule.source_file, line=rule.line_number,
            ))

        return findings

    # ------------------------------------------------------------------ #
    #  Batch helpers
    # ------------------------------------------------------------------ #

    def validate_batch(
        self,
        rules: Iterable[Union[YaraRule, SigmaRule, SuricataRule]],
    ) -> ValidationResult:
        result = ValidationResult()
        for rule in rules:
            if isinstance(rule, YaraRule):
                findings = self.validate_yara(rule)
            elif isinstance(rule, SigmaRule):
                findings = self.validate_sigma(rule)
            elif isinstance(rule, SuricataRule):
                findings = self.validate_suricata(rule)
            else:
                continue

            if any(f.severity == Severity.ERROR for f in findings):
                result.error_count += 1
            else:
                result.valid_count += 1
            for f in findings:
                result.add(f)

        return result

    def validate_path(self, path: Path | str, fmt: str = "auto") -> ValidationResult:
        """Validate rules at a file or directory path."""
        path = Path(path)
        result = ValidationResult()

        if fmt == "auto":
            fmt = _detect_format(path)

        if fmt == "yara":
            parser = YaraParser()
            try:
                rules = list(parser.parse_directory(path) if path.is_dir() else parser.parse_file(path))
            except YaraParseError as e:
                result.add(Finding(Severity.ERROR, "PARSE001", str(e), file=path))
                return result
            for rule in rules:
                for f in self.validate_yara(rule):
                    result.add(f)
                if not any(f.severity == Severity.ERROR for f in self.validate_yara(rule)):
                    result.valid_count += 1
                else:
                    result.error_count += 1

        elif fmt == "sigma":
            parser = SigmaParser()
            try:
                rules = list(parser.parse_directory(path) if path.is_dir() else [parser.parse_file(path)])
            except SigmaParseError as e:
                result.add(Finding(Severity.ERROR, "PARSE001", str(e), file=path))
                return result
            result = self.validate_batch(rules)

        elif fmt == "suricata":
            parser = SuricataParser()
            try:
                rules = list(parser.parse_directory(path) if path.is_dir() else parser.parse_file(path))
            except SuricataParseError as e:
                result.add(Finding(Severity.ERROR, "PARSE001", str(e), file=path))
                return result
            result = self.validate_batch(rules)

        return result


def _detect_format(path: Path) -> str:
    if path.is_dir():
        # Guess by majority extension
        yara = sum(1 for _ in path.glob("**/*.ya*"))
        sigma = sum(1 for _ in path.glob("**/*.yml")) + sum(1 for _ in path.glob("**/*.yaml"))
        suricata = sum(1 for _ in path.glob("**/*.rules"))
        return max((("yara", yara), ("sigma", sigma), ("suricata", suricata)), key=lambda x: x[1])[0]

    suffix = path.suffix.lower()
    if suffix in (".yar", ".yara"):
        return "yara"
    if suffix in (".yml", ".yaml"):
        return "sigma"
    if suffix == ".rules":
        return "suricata"
    return "yara"
