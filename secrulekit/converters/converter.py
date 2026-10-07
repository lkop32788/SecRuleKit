"""Sigma rule conversion engine — converts to Splunk SPL, ElasticSearch, YARA-L, QRadar AQL, Suricata."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from secrulekit.parsers.sigma_parser import SigmaRule

SUPPORTED_TARGETS = ("splunk", "elastic", "yaral", "qradar", "suricata")


class ConversionError(Exception):
    pass


class RuleConverter:
    """Convert Sigma rules to various SIEM/detection platform query languages."""

    def convert(self, rule: SigmaRule, target: str) -> str:
        target = target.lower()
        if target not in SUPPORTED_TARGETS:
            raise ConversionError(
                f"Unsupported target '{target}'. Supported: {', '.join(SUPPORTED_TARGETS)}"
            )
        method = getattr(self, f"to_{target}")
        return method(rule)

    # ------------------------------------------------------------------ #
    #  Splunk SPL
    # ------------------------------------------------------------------ #

    def to_splunk(self, rule: SigmaRule) -> str:
        """Convert Sigma rule to Splunk SPL search."""
        parts: List[str] = []
        detection = rule.detection

        for key, value in detection.items():
            if key == "condition":
                continue
            parts.extend(self._sigma_selection_to_splunk(key, value))

        condition = detection.get("condition", "selection")
        source_clause = self._logsource_to_splunk_index(rule.logsource)

        where_clauses = " AND ".join(parts) if parts else "*"
        comment = f"| `comment(\"{rule.title}\")`" if rule.title else ""
        return f"index={source_clause} {where_clauses}{comment}"

    def _sigma_selection_to_splunk(self, key: str, value: Any) -> List[str]:
        if isinstance(value, dict):
            clauses = []
            for field_name, field_val in value.items():
                field_name = field_name.replace("|contains", "").replace("|startswith", "").replace("|endswith", "")
                if isinstance(field_val, list):
                    or_parts = " OR ".join(f'{field_name}="{v}"' for v in field_val)
                    clauses.append(f"({or_parts})")
                else:
                    clauses.append(f'{field_name}="{field_val}"')
            return clauses
        if isinstance(value, list):
            return [f'"{v}"' for v in value]
        return [f'"{value}"']

    def _logsource_to_splunk_index(self, logsource: Dict[str, Any]) -> str:
        category = logsource.get("category", "")
        product = logsource.get("product", "")
        if "windows" in product.lower():
            return "wineventlog"
        if "linux" in product.lower():
            return "syslog"
        if "network" in category.lower():
            return "network"
        return "*"

    # ------------------------------------------------------------------ #
    #  ElasticSearch Query DSL
    # ------------------------------------------------------------------ #

    def to_elastic(self, rule: SigmaRule) -> str:
        """Convert Sigma rule to ElasticSearch Query DSL (JSON)."""
        must_clauses: List[Dict] = []
        detection = rule.detection

        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for field_name, field_val in value.items():
                    field_name = field_name.split("|")[0]
                    if isinstance(field_val, list):
                        must_clauses.append(
                            {"bool": {"should": [{"match": {field_name: v}} for v in field_val]}}
                        )
                    else:
                        must_clauses.append({"match": {field_name: field_val}})

        query = {
            "query": {
                "bool": {
                    "must": must_clauses if must_clauses else [{"match_all": {}}]
                }
            }
        }
        return json.dumps(query, indent=2)

    # ------------------------------------------------------------------ #
    #  YARA-L (Google SecOps / Chronicle)
    # ------------------------------------------------------------------ #

    def to_yaral(self, rule: SigmaRule) -> str:
        """Convert Sigma rule to YARA-L 2.0 skeleton."""
        safe_name = rule.title.lower().replace(" ", "_").replace("-", "_")[:64]
        meta_lines = [f'  title = "{rule.title}"']
        if rule.description:
            meta_lines.append(f'  description = "{rule.description}"')
        if rule.id:
            meta_lines.append(f'  id = "{rule.id}"')
        if rule.level:
            meta_lines.append(f'  severity = "{rule.level.upper()}"')
        for tag in rule.attack_techniques:
            meta_lines.append(f'  mitre_attack_technique = "{tag}"')

        events_lines = ["  $e.metadata.event_type = \"GENERIC_EVENT\""]
        for key, value in rule.detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for field_name, field_val in value.items():
                    field_name = field_name.split("|")[0]
                    if isinstance(field_val, list):
                        or_expr = " or ".join(f'$e.target.process.command_line = "{v}"' for v in field_val)
                        events_lines.append(f"  ({or_expr})")
                    else:
                        events_lines.append(f'  $e.target.process.command_line = "{field_val}"')

        return (
            f"rule {safe_name} {{\n"
            f"  meta:\n"
            + "\n".join(f"    {l}" for l in meta_lines) + "\n"
            f"  events:\n"
            + "\n".join(f"    {l}" for l in events_lines) + "\n"
            f"  condition:\n"
            f"    $e\n"
            f"}}\n"
        )

    # ------------------------------------------------------------------ #
    #  QRadar AQL
    # ------------------------------------------------------------------ #

    def to_qradar(self, rule: SigmaRule) -> str:
        """Convert Sigma rule to QRadar AQL query."""
        where_parts: List[str] = []

        for key, value in rule.detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for field_name, field_val in value.items():
                    field_name = field_name.split("|")[0]
                    if isinstance(field_val, list):
                        or_parts = " OR ".join(f"LOGSOURCETYPENAME(devicetype) ILIKE '%{v}%'" for v in field_val)
                        where_parts.append(f"({or_parts})")
                    else:
                        where_parts.append(f'"{field_name}" ILIKE \'%{field_val}%\'')

        where_clause = " AND ".join(where_parts) if where_parts else "1=1"
        return (
            f"SELECT UTF8(payload) as 'Payload', sourceip, destinationip, "
            f"LOGSOURCETYPENAME(devicetype) as 'Log Source Type', "
            f"CATEGORYNAME(category) as 'Category'\n"
            f"FROM events\n"
            f"WHERE {where_clause}\n"
            f"LAST 24 HOURS"
        )

    # ------------------------------------------------------------------ #
    #  Suricata
    # ------------------------------------------------------------------ #

    def to_suricata(self, rule: SigmaRule) -> str:
        """Generate a Suricata rule skeleton from a Sigma rule."""
        safe_msg = rule.title.replace('"', '\\"')
        sid = rule.id[:8].replace("-", "") if rule.id else "9000000"
        try:
            sid_int = int(sid, 16)
        except ValueError:
            sid_int = 9000000

        content_options: List[str] = []
        for key, value in rule.detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for _, field_val in value.items():
                    vals = field_val if isinstance(field_val, list) else [field_val]
                    for v in vals:
                        if isinstance(v, str) and len(v) < 128:
                            content_options.append(f'content:"{v}"; nocase;')

        options_str = " ".join(content_options) or 'content:"";'
        return (
            f'alert tcp any any -> any any '
            f'(msg:"{safe_msg}"; {options_str} '
            f'sid:{sid_int}; rev:1; '
            f'classtype:attempted-admin;)'
        )
