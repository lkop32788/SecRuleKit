"""Tests for RuleConverter."""

import textwrap
import pytest

from secrulekit.parsers.sigma_parser import SigmaParser
from secrulekit.converters.converter import RuleConverter, ConversionError

SIGMA_RULE = textwrap.dedent("""
    title: PowerShell EncodedCommand
    id: aaaabbbb-cccc-dddd-eeee-000000000001
    status: stable
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            CommandLine|contains:
                - '-EncodedCommand'
                - '-enc '
        condition: selection
    level: high
    tags:
        - attack.execution
        - attack.t1059.001
""")


@pytest.fixture
def rule():
    return SigmaParser().parse_string(SIGMA_RULE)


@pytest.fixture
def converter():
    return RuleConverter()


def test_convert_to_splunk(rule, converter):
    result = converter.to_splunk(rule)
    assert "CommandLine" in result
    assert "EncodedCommand" in result or "enc" in result.lower()


def test_convert_to_elastic(rule, converter):
    import json
    result = converter.to_elastic(rule)
    data = json.loads(result)
    assert "query" in data
    assert "bool" in data["query"]


def test_convert_to_yaral(rule, converter):
    result = converter.to_yaral(rule)
    assert "rule" in result.lower()
    assert "powershell" in result.lower() or "encoded" in result.lower()
    assert "meta:" in result


def test_convert_to_qradar(rule, converter):
    result = converter.to_qradar(rule)
    assert "SELECT" in result
    assert "FROM events" in result


def test_convert_to_suricata(rule, converter):
    result = converter.to_suricata(rule)
    assert result.startswith("alert")
    assert "sid:" in result


def test_convert_dispatch(rule, converter):
    for target in ("splunk", "elastic", "yaral", "qradar", "suricata"):
        output = converter.convert(rule, target)
        assert isinstance(output, str)
        assert len(output) > 0


def test_convert_invalid_target(rule, converter):
    with pytest.raises(ConversionError):
        converter.convert(rule, "nonexistent_target")
