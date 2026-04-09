from json import dump
from typing import Optional

from prowler.config.config import prowler_version
from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}

SEVERITY_TO_SECURITY_SEVERITY = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "4.0",
    "low": "2.0",
    "informational": "0.0",
}


class SARIF(Output):
    """Generates SARIF 2.1.0 output compatible with GitHub Code Scanning."""

    def transform(self, findings: list[Finding]) -> None:
        """Transform findings into a SARIF 2.1.0 document.

        Only FAIL findings that are not muted are included. Each unique
        check ID produces one rule entry; multiple findings for the same
        check share the rule via ruleIndex.

        Args:
            findings: List of Finding objects to transform.
        """
        rules = {}
        rule_indices = {}
        results = []

        for finding in findings:
            if finding.status != "FAIL" or finding.muted:
                continue

            check_id = finding.metadata.CheckID
            severity = finding.metadata.Severity.lower()

            if check_id not in rules:
                rule_indices[check_id] = len(rules)
                rule = {
                    "id": check_id,
                    "name": check_id,
                    "shortDescription": {"text": finding.metadata.CheckTitle},
                    "fullDescription": {
                        "text": finding.metadata.Description or check_id
                    },
                    "help": {
                        "text": finding.metadata.Remediation.Recommendation.Text
                        or finding.metadata.Description
                        or check_id,
                    },
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "note"),
                    },
                    "properties": {
                        "tags": [
                            "security",
                            f"prowler/{finding.metadata.Provider}",
                            f"severity/{severity}",
                        ],
                        "security-severity": SEVERITY_TO_SECURITY_SEVERITY.get(
                            severity, "0.0"
                        ),
                    },
                }
                if finding.metadata.RelatedUrl:
                    rule["helpUri"] = finding.metadata.RelatedUrl
                rules[check_id] = rule

            rule_index = rule_indices[check_id]
            result = {
                "ruleId": check_id,
                "ruleIndex": rule_index,
                "level": SEVERITY_TO_SARIF_LEVEL.get(severity, "note"),
                "message": {
                    "text": finding.status_extended or finding.metadata.CheckTitle
                },
            }

            location = self._build_location(finding)
            if location is not None:
                result["locations"] = [location]

            results.append(result)

        sarif_document = {
            "$schema": SARIF_SCHEMA_URL,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Prowler",
                            "version": prowler_version,
                            "informationUri": "https://prowler.com",
                            "rules": list(rules.values()),
                        },
                    },
                    "results": results,
                },
            ],
        }

        self._data = [sarif_document]

    def batch_write_data_to_file(self) -> None:
        """Write the SARIF document to the output file as JSON."""
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                dump(self._data[0], self._file_descriptor, indent=2)
                if self.close_file or self._from_cli:
                    self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def _build_location(finding: Finding) -> Optional[dict]:
        """Build a SARIF physicalLocation from a Finding.

        Uses resource_name as the artifact URI and resource_line_range
        (stored in finding.raw for IaC findings) for line range info.

        Returns:
            A SARIF location dict, or None if resource_name is empty.
        """
        if not finding.resource_name:
            return None

        location = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.resource_name,
                },
            },
        }

        line_range = finding.raw.get("resource_line_range", "")
        if line_range and ":" in line_range:
            parts = line_range.split(":")
            try:
                start_line = int(parts[0])
                end_line = int(parts[1])
                if start_line >= 1 and end_line >= 1:
                    location["physicalLocation"]["region"] = {
                        "startLine": start_line,
                        "endLine": end_line,
                    }
            except (ValueError, IndexError):
                pass  # Malformed line range — skip region, keep location

        return location
