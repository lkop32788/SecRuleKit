"""Utility functions: fingerprinting, deduplication, ATT&CK mapping."""

from __future__ import annotations

import hashlib
import re
from typing import Dict, Iterable, Iterator, List, Tuple, Union

from secrulekit.parsers.yara_parser import YaraRule
from secrulekit.parsers.sigma_parser import SigmaRule
from secrulekit.parsers.suricata_parser import SuricataRule

AnyRule = Union[YaraRule, SigmaRule, SuricataRule]

# Minimal ATT&CK technique ID → name mapping (subset for offline use)
_ATTACK_MAP: Dict[str, str] = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.004": "Unix Shell",
    "T1055": "Process Injection",
    "T1055.001": "Dynamic-link Library Injection",
    "T1055.012": "Process Hollowing",
    "T1036": "Masquerading",
    "T1027": "Obfuscated Files or Information",
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1071": "Application Layer Protocol",
    "T1071.001": "Web Protocols",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1190": "Exploit Public-Facing Application",
    "T1210": "Exploitation of Remote Services",
    "T1021": "Remote Services",
    "T1021.001": "Remote Desktop Protocol",
    "T1078": "Valid Accounts",
    "T1110": "Brute Force",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1112": "Modify Registry",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
}


def fingerprint_rule(rule: AnyRule) -> str:
    """Return a stable SHA-256 fingerprint of the rule's semantic content."""
    if isinstance(rule, YaraRule):
        payload = "|".join([
            rule.name,
            "|".join(sorted(s.value for s in rule.strings)),
            re.sub(r"\s+", " ", rule.condition),
        ])
    elif isinstance(rule, SigmaRule):
        payload = "|".join([
            rule.title,
            str(sorted(rule.detection.items())),
            str(rule.logsource),
        ])
    else:  # Suricata
        payload = "|".join([
            rule.protocol,
            rule.src_addr, rule.src_port,
            rule.dst_addr, rule.dst_port,
            rule.options.get("content", ""),
            rule.options.get("sid", ""),
        ])
    return hashlib.sha256(payload.encode()).hexdigest()


def deduplicate_rules(rules: Iterable[AnyRule]) -> Tuple[List[AnyRule], List[AnyRule]]:
    """
    Split rules into unique and duplicate lists.

    Returns (unique_rules, duplicate_rules).
    """
    seen: Dict[str, AnyRule] = {}
    duplicates: List[AnyRule] = []

    for rule in rules:
        fp = fingerprint_rule(rule)
        if fp in seen:
            duplicates.append(rule)
        else:
            seen[fp] = rule

    return list(seen.values()), duplicates


def lookup_attack_technique(technique_id: str) -> str:
    """Return the ATT&CK technique name for an ID, or empty string if unknown."""
    tid = technique_id.upper().strip()
    return _ATTACK_MAP.get(tid, "")


def iter_attack_tags(rule: SigmaRule) -> Iterator[Tuple[str, str]]:
    """Yield (technique_id, technique_name) pairs from a Sigma rule's tags."""
    for tag in rule.tags:
        if not tag.lower().startswith("attack.t"):
            continue
        tid = tag.split("attack.")[-1].upper()
        yield tid, lookup_attack_technique(tid)
