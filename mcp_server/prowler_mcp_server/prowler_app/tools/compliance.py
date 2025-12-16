"""Compliance framework tools for Prowler App MCP Server.

This module provides tools for viewing compliance status and requirement details
across all cloud providers.
"""

from typing import Any

from prowler_mcp_server.prowler_app.models.compliance import (
    ComplianceFrameworksListResponse,
    ComplianceRequirementAttributesListResponse,
    ComplianceRequirementsListResponse,
)
from prowler_mcp_server.prowler_app.tools.base import BaseTool
from pydantic import Field


class ComplianceTools(BaseTool):
    """Tools for compliance framework operations.

    Provides tools for:
    - get_compliance_overview: Get high-level compliance status across all frameworks
    - get_compliance_framework_state_details: Get detailed requirement-level breakdown for a specific framework
    """

    async def _get_latest_scan_id_for_provider(self, provider_id: str) -> str:
        """Get the latest completed scan_id for a given provider.

        Args:
            provider_id: Prowler's internal UUID for the provider

        Returns:
            The scan_id of the latest completed scan for the provider.

        Raises:
            ValueError: If no completed scans are found for the provider.
        """
        scan_params = {
            "filter[provider]": provider_id,
            "filter[state]": "completed",
            "sort": "-inserted_at",
            "page[size]": 1,
            "page[number]": 1,
        }
        clean_scan_params = self.api_client.build_filter_params(scan_params)
        scans_response = await self.api_client.get("/scans", params=clean_scan_params)

        scans_data = scans_response.get("data", [])
        if not scans_data:
            raise ValueError(
                f"No completed scans found for provider {provider_id}. "
                "Run a scan first using prowler_app_trigger_scan."
            )

        scan_id = scans_data[0]["id"]
        return scan_id

    async def get_compliance_overview(
        self,
        scan_id: str | None = Field(
            default=None,
            description="UUID of a specific scan to get compliance data for. Required if provider_id is not specified. Use `prowler_app_list_scans` to find scan IDs.",
        ),
        provider_id: str | None = Field(
            default=None,
            description="Prowler's internal UUID (v4) for a specific provider. If provided without scan_id, the tool will automatically find the latest completed scan for this provider. Use `prowler_app_search_providers` tool to find provider IDs.",
        ),
    ) -> dict[str, Any]:
        """Get high-level compliance overview across all frameworks for a specific scan.

        This tool provides a HIGH-LEVEL OVERVIEW of compliance status across all frameworks.
        Use this when you need to understand overall compliance posture before drilling into
        specific framework details.

        You have two options to specify the scan context:
        1. Provide a specific scan_id to get compliance data for that scan.
        2. Provide a provider_id to get compliance data from the latest completed scan for that provider.

        The markdown report includes:

        1. Summary Statistics:
           - Total number of compliance frameworks evaluated
           - Overall compliance metrics across all frameworks

        2. Per-Framework Breakdown:
           - Framework name, version, and compliance ID
           - Requirements passed/failed/manual counts
           - Pass percentage for quick assessment

        Workflow:
        1. Use this tool to get an overview of all compliance frameworks
        2. Use prowler_app_get_compliance_framework_state_details with a specific compliance_id to see which requirements failed
        """
        if not scan_id and not provider_id:
            return {
                "error": "Either scan_id or provider_id must be provided. Use prowler_app_search_providers to find provider IDs or prowler_app_list_scans to find scan IDs."
            }
        elif scan_id and provider_id:
            return {
                "error": "Provide either scan_id or provider_id, not both. To get compliance data for a specific scan, use scan_id. To get data for the latest scan of a provider, use provider_id."
            }
        elif not scan_id and provider_id:
            try:
                scan_id = await self._get_latest_scan_id_for_provider(provider_id)
            except ValueError as e:
                return {"error": str(e)}

        params: dict[str, Any] = {"filter[scan_id]": scan_id}

        clean_params = self.api_client.build_filter_params(params)

        # Get API response
        api_response = await self.api_client.get(
            "/compliance-overviews", params=clean_params
        )
        frameworks_response = ComplianceFrameworksListResponse.from_api_response(
            api_response
        )

        # Build markdown report
        frameworks = frameworks_response.frameworks
        total_frameworks = frameworks_response.total_count

        if total_frameworks == 0:
            return {"report": "# Compliance Overview\n\nNo compliance frameworks found"}

        # Calculate aggregate statistics
        total_requirements = sum(f.total_requirements for f in frameworks)
        total_passed = sum(f.requirements_passed for f in frameworks)
        total_failed = sum(f.requirements_failed for f in frameworks)
        total_manual = sum(f.requirements_manual for f in frameworks)
        overall_pass_pct = (
            round((total_passed / total_requirements) * 100, 1)
            if total_requirements > 0
            else 0
        )

        # Build report
        report_lines = [
            "# Compliance Overview",
            "",
            "## Summary Statistics",
            f"- **Frameworks Evaluated**: {total_frameworks}",
            f"- **Total Requirements**: {total_requirements:,}",
            f"- **Passed**: {total_passed:,} ({overall_pass_pct}%)",
            f"- **Failed**: {total_failed:,}",
            f"- **Manual Review**: {total_manual:,}",
            "",
            "## Framework Breakdown",
            "",
        ]

        # Sort frameworks by fail count (most failures first)
        sorted_frameworks = sorted(
            frameworks, key=lambda f: f.requirements_failed, reverse=True
        )

        for fw in sorted_frameworks:
            status_indicator = "PASS" if fw.requirements_failed == 0 else "FAIL"

            report_lines.append(f"### {fw.framework} {fw.version}")
            report_lines.append(f"- **Compliance ID**: `{fw.compliance_id}`")
            report_lines.append(f"- **Status**: {status_indicator}")
            report_lines.append(
                f"- **Requirements**: {fw.requirements_passed}/{fw.total_requirements} passed ({fw.pass_percentage}%)"
            )
            if fw.requirements_failed > 0:
                report_lines.append(f"- **Failed**: {fw.requirements_failed}")
            if fw.requirements_manual > 0:
                report_lines.append(f"- **Manual Review**: {fw.requirements_manual}")
            report_lines.append("")

        return {"report": "\n".join(report_lines)}

    async def _get_requirement_check_ids_mapping(
        self, compliance_id: str
    ) -> dict[str, list[str]]:
        """Get mapping of requirement IDs to their associated check IDs.

        Args:
            compliance_id: The compliance framework ID.

        Returns:
            Dictionary mapping requirement ID to list of check IDs.
        """
        params: dict[str, Any] = {
            "filter[compliance_id]": compliance_id,
            "fields[compliance-requirements-attributes]": "id,attributes",
        }

        clean_params = self.api_client.build_filter_params(params)

        api_response = await self.api_client.get(
            "/compliance-overviews/attributes", params=clean_params
        )
        attributes_response = (
            ComplianceRequirementAttributesListResponse.from_api_response(api_response)
        )

        # Build mapping: requirement_id -> [check_ids]
        return {req.id: req.check_ids for req in attributes_response.requirements}

    async def _get_failed_finding_ids_for_checks(
        self,
        check_ids: list[str],
        scan_id: str,
    ) -> list[str]:
        """Get all failed finding IDs for a list of check IDs.

        Args:
            check_ids: List of Prowler check IDs.
            scan_id: The scan ID to filter findings.

        Returns:
            List of all finding IDs with FAIL status.
        """
        if not check_ids:
            return []

        all_finding_ids: list[str] = []
        page_number = 1
        page_size = 100

        while True:
            # Query findings endpoint with check_id filter and FAIL status
            params: dict[str, Any] = {
                "filter[scan]": scan_id,
                "filter[check_id__in]": ",".join(check_ids),
                "filter[status]": "FAIL",
                "fields[findings]": "uid",
                "page[size]": page_size,
                "page[number]": page_number,
            }

            clean_params = self.api_client.build_filter_params(params)

            api_response = await self.api_client.get("/findings", params=clean_params)

            findings = api_response.get("data", [])
            if not findings:
                break

            all_finding_ids.extend([f["id"] for f in findings])

            # Check if we've reached the last page
            if len(findings) < page_size:
                break

            page_number += 1

        return all_finding_ids

    async def get_compliance_framework_state_details(
        self,
        compliance_id: str = Field(
            description="Compliance framework ID to get details for (e.g., 'cis_1.5_aws', 'pci_dss_v4.0_aws'). You can get compliance IDs from prowler_app_get_compliance_overview or consulting Prowler Hub/Prowler Documentation that you can also find in form of tools in this MCP Server",
        ),
        scan_id: str | None = Field(
            default=None,
            description="UUID of a specific scan to get compliance data for. Required if provider_id is not specified.",
        ),
        provider_id: str | None = Field(
            default=None,
            description="Prowler's internal UUID (v4) for a specific provider. If provided without scan_id, the tool will automatically find the latest completed scan for this provider. Use `prowler_app_search_providers` tool to find provider IDs.",
        ),
    ) -> dict[str, Any]:
        """Get detailed requirement-level breakdown for a specific compliance framework.

        IMPORTANT: This tool returns DETAILED requirement information for a single compliance framework,
        focusing on FAILED requirements and their associated FAILED finding IDs.
        Use this after prowler_app_get_compliance_overview to drill down into specific frameworks.

        The markdown report includes:

        1. Framework Summary:
           - Compliance ID and scan ID used
           - Overall pass/fail/manual counts

        2. Failed Requirements Breakdown:
           - Each failed requirement's ID and description
           - Associated failed finding IDs for each failed requirement
           - Use prowler_app_get_finding_details with these finding IDs for more details and remediation guidance

        Default behavior:
        - Requires either scan_id OR provider_id
        - With provider_id (no scan_id): Automatically finds the latest completed scan for that provider
        - With scan_id: Uses that specific scan's compliance data
        - Only shows failed requirements with their associated failed finding IDs

        Workflow:
        1. Use prowler_app_get_compliance_overview to identify frameworks with failures
        2. Use this tool with the compliance_id to see failed requirements and their finding IDs
        3. Use prowler_app_get_finding_details with the finding IDs to get remediation guidance
        """
        # Validate that either scan_id or provider_id is provided
        if not scan_id and not provider_id:
            return {
                "error": "Either scan_id or provider_id must be provided. Use prowler_app_search_providers to find provider IDs or prowler_app_list_scans to find scan IDs."
            }

        # Resolve provider_id to latest scan_id if needed
        resolved_scan_id = scan_id
        if not scan_id and provider_id:
            try:
                resolved_scan_id = await self._get_latest_scan_id_for_provider(
                    provider_id
                )
            except ValueError as e:
                return {"error": str(e)}

        # Build params for requirements endpoint
        params: dict[str, Any] = {
            "filter[scan_id]": resolved_scan_id,
            "filter[compliance_id]": compliance_id,
        }

        params["fields[compliance-requirements-details]"] = "id,description,status"

        clean_params = self.api_client.build_filter_params(params)

        # Get API response
        api_response = await self.api_client.get(
            "/compliance-overviews/requirements", params=clean_params
        )
        requirements_response = ComplianceRequirementsListResponse.from_api_response(
            api_response
        )

        requirements = requirements_response.requirements

        if not requirements:
            return {
                "report": f"# Compliance Framework Details\n\n**Compliance ID**: `{compliance_id}`\n\nNo requirements found for this compliance framework and scan combination."
            }

        # Get failed requirements
        failed_reqs = [r for r in requirements if r.status == "FAIL"]

        # Get requirement -> check_ids mapping from attributes endpoint
        requirement_check_mapping: dict[str, list[str]] = {}
        if failed_reqs:
            requirement_check_mapping = await self._get_requirement_check_ids_mapping(
                compliance_id
            )

        # For each failed requirement, get the failed finding IDs
        failed_req_findings: dict[str, list[str]] = {}
        for req in failed_reqs:
            check_ids = requirement_check_mapping.get(req.id, [])
            if check_ids:
                finding_ids = await self._get_failed_finding_ids_for_checks(
                    check_ids, resolved_scan_id
                )
                failed_req_findings[req.id] = finding_ids

        # Calculate counts
        total_count = len(requirements)
        passed_count = sum(1 for r in requirements if r.status == "PASS")
        failed_count = len(failed_reqs)
        manual_count = sum(1 for r in requirements if r.status == "MANUAL")

        # Build markdown report
        pass_pct = (
            round((passed_count / total_count) * 100, 1) if total_count > 0 else 0
        )

        report_lines = [
            "# Compliance Framework Details",
            "",
            f"**Compliance ID**: `{compliance_id}`",
            f"**Scan ID**: `{resolved_scan_id}`",
            "",
            "## Summary",
            f"- **Total Requirements**: {total_count}",
            f"- **Passed**: {passed_count} ({pass_pct}%)",
            f"- **Failed**: {failed_count}",
            f"- **Manual Review**: {manual_count}",
            "",
        ]

        # Show failed requirements with their finding IDs (most actionable)
        if failed_reqs:
            report_lines.append("## Failed Requirements")
            report_lines.append("")
            for req in failed_reqs:
                report_lines.append(f"### {req.id}")
                report_lines.append(f"**Description**: {req.description}")
                finding_ids = failed_req_findings.get(req.id, [])
                if finding_ids:
                    report_lines.append(f"**Failed Finding IDs** ({len(finding_ids)}):")
                    for fid in finding_ids:
                        report_lines.append(f"  - `{fid}`")
                else:
                    report_lines.append("**Failed Finding IDs**: None found")
                report_lines.append("")
            report_lines.append(
                "*Use `prowler_app_get_finding_details` with these finding IDs to get remediation guidance.*"
            )
            report_lines.append("")

        if manual_count > 0:
            manual_reqs = [r for r in requirements if r.status == "MANUAL"]
            report_lines.append("## Requirements Requiring Manual Review")
            report_lines.append("")
            for req in manual_reqs:
                report_lines.append(f"- **{req.id}**: {req.description}")
            report_lines.append("")

        return {"report": "\n".join(report_lines)}
