"""Tests for YARA, Sigma, and Suricata parsers."""

import textwrap
import pytest

from secrulekit.parsers.yara_parser import YaraParser, YaraParseError
from secrulekit.parsers.sigma_parser import SigmaParser, SigmaParseError
from secrulekit.parsers.suricata_parser import SuricataParser, SuricataParseError


# ------------------------------------------------------------------ #
#  YARA parser
# ------------------------------------------------------------------ #

YARA_SAMPLE = textwrap.dedent("""
    rule DetectMimikatz : credential_access {
        meta:
            description = "Detects Mimikatz strings"
            author = "SecRuleKit Tests"
        strings:
            $s1 = "sekurlsa" nocase
            $s2 = "lsadump" nocase
            $hex = { 4D 69 6D 69 6B 61 74 7A }
        condition:
            any of them
    }

    rule EmptyCondition {
        strings:
            $a = "test"
        condition:
            $a
    }
""")


def test_yara_parse_rule_name():
    parser = YaraParser()
    rules = parser.parse_string(YARA_SAMPLE)
    assert len(rules) == 2
    assert rules[0].name == "DetectMimikatz"


def test_yara_parse_tags():
    rules = YaraParser().parse_string(YARA_SAMPLE)
    assert "credential_access" in rules[0].tags


def test_yara_parse_strings():
    rules = YaraParser().parse_string(YARA_SAMPLE)
    string_names = [s.name for s in rules[0].strings]
    assert "$s1" in string_names
    assert "$hex" in string_names


def test_yara_parse_meta():
    rules = YaraParser().parse_string(YARA_SAMPLE)
    assert rules[0].meta.get("author") == "SecRuleKit Tests"


def test_yara_parse_condition():
    rules = YaraParser().parse_string(YARA_SAMPLE)
    assert "any of them" in rules[0].condition


def test_yara_empty_string():
    rules = YaraParser().parse_string("")
    assert rules == []


def test_yara_string_types():
    rules = YaraParser().parse_string(YARA_SAMPLE)
    types = {s.name: s.type for s in rules[0].strings}
    assert types["$s1"] == "text"
    assert types["$hex"] == "hex"


# ------------------------------------------------------------------ #
#  Sigma parser
# ------------------------------------------------------------------ #

SIGMA_SAMPLE = textwrap.dedent("""
    title: PowerShell Encoded Command
    id: a6f79f21-4c23-4c12-8e0a-deadbeef0001
    status: stable
    description: Detects PowerShell running encoded commands
    author: SecRuleKit Tests
    date: 2026-01-01
    tags:
        - attack.execution
        - attack.t1059.001
    logsource:
        category: process_creation
        product: windows
    detection:
        selection:
            CommandLine|contains:
                - '-EncodedCommand'
                - '-enc '
                - '-ec '
        condition: selection
    level: high
    falsepositives:
        - Legitimate admin scripts
""")


def test_sigma_parse_title():
    rule = SigmaParser().parse_string(SIGMA_SAMPLE)
    assert rule.title == "PowerShell Encoded Command"


def test_sigma_parse_id():
    rule = SigmaParser().parse_string(SIGMA_SAMPLE)
    assert rule.id == "a6f79f21-4c23-4c12-8e0a-deadbeef0001"


def test_sigma_parse_tags():
    rule = SigmaParser().parse_string(SIGMA_SAMPLE)
    assert "attack.t1059.001" in rule.tags


def test_sigma_attack_techniques():
    rule = SigmaParser().parse_string(SIGMA_SAMPLE)
    assert "T1059.001" in rule.attack_techniques


def test_sigma_parse_level():
    rule = SigmaParser().parse_string(SIGMA_SAMPLE)
    assert rule.level == "high"


def test_sigma_parse_logsource():
    rule = SigmaParser().parse_string(SIGMA_SAMPLE)
    assert rule.logsource["product"] == "windows"


def test_sigma_missing_title():
    with pytest.raises(SigmaParseError, match="title"):
        SigmaParser().parse_string("detection:\n  condition: selection\n")


def test_sigma_missing_detection():
    with pytest.raises(SigmaParseError, match="detection"):
        SigmaParser().parse_string("title: Test Rule\n")


# ------------------------------------------------------------------ #
#  Suricata parser
# ------------------------------------------------------------------ #

SURICATA_SAMPLE = (
    'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS '
    '(msg:"ET MALWARE Suspicious User-Agent"; content:"Mozilla/4.0 (compatible)"; '
    'nocase; http_header; sid:2001234; rev:5; classtype:trojan-activity;)'
)


def test_suricata_parse_action():
    rule = SuricataParser().parse_string(SURICATA_SAMPLE)
    assert rule.action == "alert"


def test_suricata_parse_protocol():
    rule = SuricataParser().parse_string(SURICATA_SAMPLE)
    assert rule.protocol == "tcp"


def test_suricata_parse_sid():
    rule = SuricataParser().parse_string(SURICATA_SAMPLE)
    assert rule.sid == "2001234"


def test_suricata_parse_msg():
    rule = SuricataParser().parse_string(SURICATA_SAMPLE)
    assert "Suspicious User-Agent" in rule.msg


def test_suricata_blank_line():
    assert SuricataParser().parse_string("") is None
    assert SuricataParser().parse_string("# comment") is None


def test_suricata_invalid():
    with pytest.raises(SuricataParseError):
        SuricataParser().parse_string("not a rule")
