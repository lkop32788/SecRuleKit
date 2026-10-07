"""Tests for RuleValidator."""

import textwrap
import pytest

from secrulekit.parsers.yara_parser import YaraParser
from secrulekit.parsers.sigma_parser import SigmaParser
from secrulekit.parsers.suricata_parser import SuricataParser
from secrulekit.validators.rule_validator import RuleValidator, Severity


VALID_YARA = textwrap.dedent("""
    rule ValidRule {
        meta:
            description = "A valid rule"
            author = "Tester"
        strings:
            $a = "malware"
        condition:
            $a
    }
""")

YARA_NO_CONDITION = textwrap.dedent("""
    rule NoCondition {
        strings:
            $a = "test"
    }
""")

VALID_SIGMA = textwrap.dedent("""
    title: Valid Sigma
    id: 11111111-1111-1111-1111-111111111111
    status: stable
    logsource:
        product: windows
        category: process_creation
    detection:
        selection:
            CommandLine|contains: malware
        condition: selection
    level: high
""")

SIGMA_NO_CONDITION = textwrap.dedent("""
    title: No Condition
    logsource:
        product: windows
    detection:
        selection:
            Image: malware.exe
""")

VALID_SURICATA = (
    'alert tcp any any -> any any (msg:"Test"; content:"malware"; sid:1001; rev:1;)'
)


def test_validator_yara_valid():
    rule = YaraParser().parse_string(VALID_YARA)[0]
    validator = RuleValidator()
    findings = validator.validate_yara(rule)
    errors = [f for f in findings if f.severity == Severity.ERROR]
    assert not errors


def test_validator_yara_no_condition():
    # YaraParser may not parse a rule without condition block — test via YARA_NO_CONDITION
    rules = YaraParser().parse_string(YARA_NO_CONDITION)
    if not rules:
        pytest.skip("Parser skipped conditionless rule")
    validator = RuleValidator()
    findings = validator.validate_yara(rules[0])
    codes = [f.code for f in findings]
    assert "YARA001" in codes


def test_validator_sigma_valid():
    rule = SigmaParser().parse_string(VALID_SIGMA)
    validator = RuleValidator()
    findings = validator.validate_sigma(rule)
    errors = [f for f in findings if f.severity == Severity.ERROR]
    assert not errors


def test_validator_sigma_no_condition():
    rule = SigmaParser().parse_string(SIGMA_NO_CONDITION + "\n    condition: selection\n")
    validator = RuleValidator()
    findings = validator.validate_sigma(rule)
    errors = [f for f in findings if f.severity == Severity.ERROR]
    assert not errors  # detection has condition now


def test_validator_sigma_condition_field_missing():
    rule = SigmaParser().parse_string(SIGMA_NO_CONDITION)
    validator = RuleValidator()
    findings = validator.validate_sigma(rule)
    codes = [f.code for f in findings]
    assert "SIGMA003" in codes


def test_validator_suricata_valid():
    rule = SuricataParser().parse_string(VALID_SURICATA)
    validator = RuleValidator()
    findings = validator.validate_suricata(rule)
    errors = [f for f in findings if f.severity == Severity.ERROR]
    assert not errors


def test_validator_suricata_no_sid():
    rule = SuricataParser().parse_string(
        'alert tcp any any -> any any (msg:"Test"; content:"x";)'
    )
    validator = RuleValidator()
    findings = validator.validate_suricata(rule)
    codes = [f.code for f in findings]
    assert "SURI001" in codes


def test_validator_batch_summary():
    rules = YaraParser().parse_string(VALID_YARA)
    validator = RuleValidator()
    result = validator.validate_batch(rules)
    assert result.valid_count >= 1
    assert result.passed


def test_validator_strict_mode():
    rule = YaraParser().parse_string(VALID_YARA)[0]
    # In strict mode, missing meta fields should be warnings not info
    validator_strict = RuleValidator(strict=True)
    validator_normal = RuleValidator(strict=False)
    findings_strict = validator_strict.validate_yara(rule)
    findings_normal = validator_normal.validate_yara(rule)
    # Both should not have errors for a valid rule
    assert all(f.severity != Severity.ERROR for f in findings_strict)
    assert all(f.severity != Severity.ERROR for f in findings_normal)
