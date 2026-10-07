"""JSON audit report reporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from secrulekit.validators.rule_validator import ValidationResult


class JsonReporter:
    """Write validation results as a JSON report."""

    def generate(self, result: ValidationResult, output: Optional[Path | str] = None) -> str:
        data = {
            "summary": {
                "valid": result.valid_count,
                "errors": result.error_count,
                "warnings": result.warning_count,
                "passed": result.passed,
            },
            "findings": [
                {
                    "severity": f.severity.value,
                    "code": f.code,
                    "message": f.message,
                    "rule": f.rule_name,
                    "file": str(f.file) if f.file else None,
                    "line": f.line,
                }
                for f in result.findings
            ],
        }
        text = json.dumps(data, indent=2, ensure_ascii=False)
        if output:
            Path(output).write_text(text, encoding="utf-8")
        return text
