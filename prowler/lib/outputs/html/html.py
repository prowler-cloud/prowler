import html
import json
import sys
from io import TextIOWrapper

from prowler.config.config import (
    html_logo_url,
    prowler_version,
    square_logo_img,
    timestamp,
)
from prowler.lib.logger import logger
from prowler.lib.outputs.output import Finding, Output
from prowler.providers.common.provider import Provider


class HTML(Output):
    def transform(self, findings: list[Finding]) -> None:
        """Transforms the findings into the HTML format.

        Args:
            findings (list[Finding]): a list of Finding objects

        """
        try:
            for finding in findings:
                row_class = "p-3 mb-2 bg-success-custom"
                finding_status = finding.status.value
                status_order = "2"  # Default for PASS
                if finding.status == "FAIL":
                    status_order = "1"
                    row_class = "table-danger"
                elif finding.status == "MANUAL":
                    status_order = "3"
                    row_class = "table-info"

                # Change the status of the finding if it's muted
                if finding.muted:
                    finding_status = f"MUTED ({finding_status})"
                    # Muted FAIL should still sort as FAIL, Muted PASS as PASS
                    if finding.status == "FAIL":  # Original status before muting
                        row_class = "table-warning"  # Muted FAIL is warning
                    # else: Muted PASS remains success-custom or its original class if not FAIL

                severity_value = finding.metadata.Severity.value.lower()
                severity_order = "5"  # Default for informational or unknown
                if severity_value == "critical":
                    severity_order = "1"
                elif severity_value == "high":
                    severity_order = "2"
                elif severity_value == "medium":
                    severity_order = "3"
                elif severity_value == "low":
                    severity_order = "4"

                # Prepare raw data for complex fields
                raw_tags_json_string = json.dumps(
                    finding.resource_tags if finding.resource_tags else {}
                )
                raw_compliance_json_string = json.dumps(
                    finding.compliance if finding.compliance else {}
                )

                self._data.append(
                    f"""
                        <tr class="severity-{severity_value}"
                            data-risk-raw="{html.escape(finding.metadata.Risk)}"
                            data-status-extended-raw="{html.escape(finding.status_extended)}"
                            data-remediation-text-raw="{html.escape(finding.metadata.Remediation.Recommendation.Text)}"
                            data-remediation-url="{finding.metadata.Remediation.Recommendation.Url}"
                            data-description-raw="{html.escape(finding.metadata.CheckTitle)}"
                            data-check-id-raw="{html.escape(finding.metadata.CheckID)}"
                            data-resource-tags-raw='{raw_tags_json_string}'
                            data-compliance-raw='{raw_compliance_json_string}'>
                            <td data-order="{status_order}" data-filter="{finding_status}"><span class="chip status-chip status-{row_class}">{finding_status}</span></td>
                            <td data-order="{severity_order}" data-filter="{finding.metadata.Severity.value}"><span class="chip severity-chip severity-{severity_value}">{finding.metadata.Severity.value}</span></td>
                            <td data-filter="{finding.metadata.ServiceName}"><span class="chip service-chip">{finding.metadata.ServiceName}</span></td>
                            <td class="monospace-font" data-filter="{finding.region.lower()}">{finding.region.lower()}</td>
                            <td class="monospace-font" data-filter="{finding.metadata.CheckID}"><a href="https://hub.prowler.com/check/{finding.metadata.CheckID}" target="_blank">{finding.metadata.CheckID.replace("_", "<wbr />_")}</a></td>
                            <td class="monospace-font">{finding.resource_uid.replace("<", "&lt;").replace(">", "&gt;").replace("_", "<wbr />_")}</td>
                            <td class="monospace-font" data-filter="{finding.resource_type if finding.resource_type else ''}">{finding.resource_type if finding.resource_type else ''}</td>
                        </tr>
                        """
                )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def batch_write_data_to_file(self, provider: Provider, stats: dict) -> None:
        """
        Writes the findings to a file using the HTML format using the `Output._file_descriptor`.

        Args:
            provider (Provider): the provider object
            output_filename (str): the name of the output file
            output_directory (str): the directory where the output file will be saved
            stats (dict): the statistics of the findings
        """
        try:
            if (
                getattr(self, "_file_descriptor", None)
                and not self._file_descriptor.closed
                and self._data
            ):
                if self._file_descriptor.tell() == 0:
                    HTML.write_header(
                        self._file_descriptor, provider, stats, self._from_cli
                    )
                for finding in self._data:
                    self._file_descriptor.write(finding)
                if self.close_file or self._from_cli:
                    HTML.write_footer(self._file_descriptor)
                    self._file_descriptor.close()
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def write_header(
        file_descriptor: TextIOWrapper,
        provider: Provider,
        stats: dict,
        from_cli: bool = True,
    ) -> None:
        """
        Writes the header of the HTML file.

        Args:
            file_descriptor (file): the file descriptor to write the header
            provider (Provider): the provider object
            stats (dict): the statistics of the findings
            from_cli (bool): whether the request is from the CLI or not
        """
        try:
            file_descriptor.write(
                f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <!-- Required meta tags -->
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
    <style>
        body {{
            margin: 0; /* Ensure no default body margins */
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; /* Prioritize Inter */
            font-size: 0.875rem; /* Slightly smaller base font */
            background-color: #f8f9fa; /* Light gray background */
            color: #212529; /* Default text color */
            transition: background-color 0.3s, color 0.3s;
        }}
        .container-fluid {{
            padding-left: 15px; /* Maintain some padding */
            padding-right: 15px;
            width: 100%;
            box-sizing: border-box;
        }}
        .read-more {{color: #007bff; text-decoration: none;}}
        .read-more:hover {{text-decoration: underline;}}

        .bg-success-custom {{background-color: #d4edda !important; color: #155724;}} /* Softer success green */
        .bg-danger {{background-color: #f8d7da !important; color: #721c24;}} /* Softer danger red */
        .table-info {{background-color: #d1ecf1 !important; color: #0c5460;}} /* Softer info blue */
        .table-warning {{background-color: #fff3cd !important; color: #856404;}} /* Softer warning yellow */

        /* Card styles */
        .card {{
            border: 1px solid #e5e7eb; /* Tailwind gray-200 */
            box-shadow: 0 4px 6px -1px rgba(0,0,0,.07), 0 2px 4px -2px rgba(0,0,0,.05); /* Modern shadow */
            margin-bottom: 1.75rem; /* Increased spacing */
            border-radius: 0.5rem; /* More rounded corners */
            background-color: #fff; /* Ensure card background is white */
        }}
        .card-header {{
            background-color: #f9fafb; /* Tailwind gray-50 */
            color: #1f2937; /* Tailwind gray-800 */
            font-weight: 600; /* Semibold */
            padding: 0.65rem 1rem; /* Reduced padding */
            border-bottom: 1px solid #e5e7eb; /* Tailwind gray-200 */
            border-top-left-radius: 0.5rem; /* Match card radius */
            border-top-right-radius: 0.5rem; /* Match card radius */
        }}
        .card .list-group-item {{
            background-color: #fff; /* Ensure list items have white background */
            padding: 0.65rem 1rem; /* Reduced padding */
            border-bottom: 1px solid #f3f4f6; /* Tailwind gray-100 for subtle separation */
        }}
        .card .list-group-item:last-child {{
            border-bottom: none; /* Remove border from last item */
        }}
        .card .list-group-item b {{
            font-weight: 500; /* Medium weight */
            color: #374151; /* Tailwind gray-700 */
            margin-right: 0.5rem;
        }}

        /* Assessment Overview Card Specific Styles */
        #assessmentOverviewCard .list-group-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        #assessmentOverviewCard .list-group-item span.value {{
            font-weight: 600;
            font-size: 0.95rem;
            color: #111827; /* Tailwind gray-900 */
            margin-left: auto; /* Push value to the right, bar will be in between */
            padding-left: 0.5rem; /* Space between bar and value */
        }}

        /* Tiny graph for assessment overview */
        .overview-bar-container {{
            flex-grow: 1;
            height: 10px; /* Height of the bar track */
            background-color: #e5e7eb; /* Tailwind gray-200 for the track */
            border-radius: 5px;
            margin: 0 0.75rem; /* Space around the bar container */
            overflow: hidden; /* Ensure bar stays within rounded corners */
        }}
        .overview-bar {{
            height: 100%;
            display: block;
            border-radius: 5px;
        }}
        .overview-bar-passed {{
            background-color: #28a745; /* Green for passed */
        }}
        .overview-bar-failed {{
            background-color: #dc3545; /* Red for failed */
        }}

        /* Table specific styles */
        .table-responsive-container {{
            width: 100%;
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
            margin-top: 2rem; /* Increased top margin */
            margin-bottom: 2rem; /* Added bottom margin */
            border: 1px solid #dee2e6; /* Border around the container/table */
            border-radius: 0.375rem; /* Rounded corners for the container */
            box-shadow: 0 0.125rem 0.35rem rgba(0,0,0,.075); /* Subtle shadow for the table container */
        }}
        #findingsTable {{
            width: 100%;
            min-width: 900px;
            border-collapse: collapse;
            /* border: 1px solid #dee2e6; Moved to container */
        }}
        #findingsTable th,
        #findingsTable td {{
            padding: 0.85rem 0.75rem; /* Adjusted padding inspired by security-ai.html */
            vertical-align: top; /* Changed from middle to top */
            border-top: none;
            border-bottom: 1px solid #e5e7eb; /* Tailwind gray-200 for row separation */
            text-align: left;
        }}
        #findingsTable tr:last-child td {{
            border-bottom: none;
        }}
        #findingsTable thead th {{
            background-color: #F1F3F5 !important; /* Updated background */
            color: #374151 !important; /* Tailwind gray-700 */
            border-bottom: 1px solid #DDE1E6 !important; /* Thinner and lighter bottom border */
            font-weight: 600 !important; /* Tailwind font-semibold */
            font-size: 0.8rem !important; /* Slightly increased font size */
            text-transform: uppercase !important;
            letter-spacing: 0.05em !important;
            padding: 0.9rem 0.75rem !important; /* Adjusted padding for new font size */
            vertical-align: middle !important; /* Ensure vertical alignment */
        }}
        #findingsTable tbody tr {{
            cursor: pointer;
        }}
        #findingsTable tbody tr:hover {{
            background-color: #f9fafb; /* Tailwind gray-50 for hover */
        }}
        #findingsTable td {{ /* Specific overrides for td if th settings are too general */
            color: #4b5563; /* Tailwind gray-600 for cell text */
        }}

        /* Chip styles */
        .chip {{
            display: inline-block;
            padding: .35em .65em; /* Increased padding */
            font-size: 80%;      /* Slightly increased font-size */
            font-weight: 700;
            line-height: 1;
            text-align: center;
            white-space: nowrap;
            vertical-align: baseline;
            border-radius: .35rem; /* Slightly larger radius */
        }}
        .status-chip.status-table-danger {{ background-color: #f8d7da; color: #721c24; }}
        .status-chip.status-table-success {{ background-color: #d4edda; color: #155724; }}
        .status-chip.status-table-info {{ background-color: #d1ecf1; color: #0c560; }}
        .status-chip.status-table-warning {{ background-color: #fff3cd; color: #856404; }}
        .severity-chip.severity-critical {{ background-color: #dc3545; color: white; }}
        .severity-chip.severity-high {{ background-color: #fd7e14; color: white; }}
        .severity-chip.severity-medium {{ background-color: #ffc107; color: #212529; }}
        .severity-chip.severity-low {{ background-color: #28a745; color: white; }}
        .severity-chip.severity-informational {{ background-color: #17a2b8; color: white; }}
        .service-chip {{
            background-color: #6c757d; /* Bootstrap secondary color */
            color: white;
        }}

        /* Monospace font style */
        .monospace-font {{
            font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 0.9em; /* Adjust size if needed, slightly smaller than base for monospace */
        }}

        /* Modal Styles (inspired by security-ai.html) */
        .prowler-modal-backdrop {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.6);
            display: flex; /* Use flex for centering */
            justify-content: center;
            align-items: center;
            z-index: 1050; /* Higher than DataTables sticky header */
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.3s ease, visibility 0s linear 0.3s;
        }}
        .prowler-modal-backdrop.visible {{
            opacity: 1;
            visibility: visible;
            transition: opacity 0.3s ease;
        }}
        .prowler-modal-content {{
            background-color: #ffffff;
            padding: 1.5rem; /* 24px */
            border-radius: 0.5rem; /* 8px */
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            max-width: 65%; /* Adjusted from 61% for potentially more content */
            width: 90%;
            max-height: 85vh;
            overflow-y: auto;
            position: relative;
            display: flex;
            flex-direction: column;
            transform: scale(0.95);
            transition: transform 0.3s ease;
        }}
        .prowler-modal-backdrop.visible .prowler-modal-content {{
            transform: scale(1);
        }}
        .prowler-modal-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem; /* 16px */
            padding-bottom: 0.75rem; /* 12px */
            border-bottom: 1px solid #e5e7eb; /* Tailwind gray-200 */
        }}
        .prowler-modal-title {{
            font-size: 1.25rem; /* 20px, adjusted from 1.125rem */
            font-weight: 600;
            color: #1f2937; /* Tailwind gray-800 */
            flex-grow: 1;
            margin-right: 1rem;
            line-height: 1.4;
        }}
        .prowler-modal-close-btn {{
            background: none;
            border: none;
            font-size: 2rem; /* Larger close button */
            line-height: 1;
            cursor: pointer;
            color: #9ca3af; /* Tailwind gray-400 */
            padding: 0.25rem;
        }}
        .prowler-modal-close-btn:hover {{
            color: #1f2937; /* Tailwind gray-800 */
        }}
        .prowler-modal-body {{
            font-size: 0.875rem; /* 14px */
            color: #374151; /* Tailwind gray-700 */
            line-height: 1.6;
            flex-grow: 1; /* Allows body to take available space for scrolling */
        }}
        .prowler-modal-section {{
            margin-bottom: 1.25rem; /* 20px */
        }}
        .prowler-modal-section h4 {{
            font-size: 1rem; /* 16px */
            font-weight: 600;
            color: #111827; /* Tailwind gray-900 */
            margin-bottom: 0.625rem; /* 10px */
            padding-bottom: 0.375rem; /* 6px */
            border-bottom: 1px solid #e5e7eb; /* Tailwind gray-200 */
        }}
        .prowler-modal-row {{
            display: flex;
            margin-bottom: 0.5rem; /* 8px */
            flex-wrap: wrap; /* Allow wrapping for long content */
        }}
        .prowler-modal-label {{
            font-weight: 500;
            color: #4b5563; /* Tailwind gray-600 */
            width: 200px; /* Increased width for potentially longer labels */
            flex-shrink: 0;
            margin-right: 1rem;
            padding-bottom: 0.25rem;
            font-size: 0.825rem; /* Slightly smaller label text */
        }}
        .prowler-modal-value {{
            flex-grow: 1;
            white-space: pre-wrap;
            word-break: break-word;
            color: #1f2937; /* Tailwind gray-800 */
            font-size: 0.875rem; /* Ensure value text is clear */
        }}
        .prowler-modal-value a {{
            color: #007bff;
            text-decoration: underline;
        }}
        .prowler-modal-value code, .prowler-modal-value pre {{
            background-color: #f3f4f6; /* Tailwind gray-100 */
            padding: 0.2em 0.4em;
            border-radius: 0.25rem; /* 4px */
            font-size: 0.9em;
            white-space: pre-wrap;
            word-break: break-all; /* Ensure long code strings break */
        }}
        .prowler-modal-value pre {{
            padding: 0.75em;
            overflow-x: auto;
        }}
        .prowler-modal-value ul, .prowler-modal-value ol {{
            margin-left: 1.5em;
            padding-left: 0; /* Reset browser default */
        }}
        .prowler-modal-value li {{
            margin-bottom: 0.25em;
        }}
        /* Compact header chips in modal */
        .modal-header-chips {{
            display: flex;
            flex-wrap: wrap;
            align-items: baseline; /* Align items based on their text baseline */
            gap: 0.5rem 1.25rem; /* row-gap column-gap, adjusted for more space between items */
            margin-bottom: 1rem; /* 16px */
            padding-bottom: 1rem;
            border-bottom: 1px solid #e5e7eb;
        }}
        .modal-header-chips .chip-item {{
            display: flex;
            align-items: center; /* Align label and chip on the same line */
            gap: 0.4rem; /* Space between label and its chip */
        }}
        .modal-header-chips .chip-label {{
            font-size: 0.8rem; /* Slightly larger label */
            color: #4b5563; /* Tailwind gray-600, was #6b7280 */
            font-weight: 500; /* Medium weight for labels */
            /* margin-bottom: 0; removed as they are inline now */
        }}
        .modal-header-chips .chip {{
            padding: .25em .6em; /* Slightly more padding for chips */
            font-size: 0.8rem; /* Slightly larger chip text */
        }}

        /* Styles for collapsible sections */
        .prowler-modal-section-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            padding: 0.6rem 0.1rem; /* Adjusted padding, less horizontal */
            /* margin-bottom: 0.625rem; /* Removed, spacing handled by section */
            border-bottom: 1px solid #e5e7eb; /* Tailwind gray-200 */
        }}
        .prowler-modal-section-header:hover {{
            background-color: #f9fafb; /* Light hover for the header too */
        }}
        .prowler-modal-section-header h4 {{
            font-size: 1rem; /* 16px */
            font-weight: 600;
            color: #111827; /* Tailwind gray-900 */
            margin-bottom: 0;
            border-bottom: none;
        }}
        .prowler-modal-section-toggle {{
            font-size: 1.1rem; /* Slightly smaller toggle */
            transition: transform 0.2s ease-in-out;
            color: #6b7280; /* Tailwind gray-500 */
            padding: 0.25rem; /* Make it easier to click */
        }}
        .prowler-modal-section-content {{
            padding: 0.8rem 1rem;
            background-color: #f9fafb;
            border: 1px solid #e5e7eb;
            border-top: none;
            border-radius: 0 0 0.375rem 0.375rem;
            margin-bottom: 1rem;
        }}
        /* Conditional styling for FAIL in Risk & Remediation */
        .prowler-modal-section-content.fail-highlight {{
            background-color: #fef2f2; /* Tailwind red-50 */
            border-color: #fecaca; /* Tailwind red-200 */
        }}
        .prowler-modal-section-content.collapsed {{
            display: none;
        }}
        .prowler-modal-section-header .prowler-modal-section-toggle.collapsed {{
            transform: rotate(-90deg);
        }}

        /* Ensure the first section header has rounded top corners if its content is also card-like */
        .prowler-modal-section:first-child .prowler-modal-section-header {{
            /* border-radius: 0.375rem 0.375rem 0 0; */ /* Causing issues with border */
        }}
        /* Ensure the last section content card has spacing if needed, already handled by margin-bottom */

        /* Styles for improved compliance display */
        .compliance-standard-item {{
            margin-bottom: 0.75rem; /* Space between different standards */
            padding: 0.6rem 0.8rem; /* Slightly more padding */
            background-color: #f9fafb; /* Tailwind gray-50, was #f9f9f9 */
            border-radius: 0.375rem; /* Tailwind rounded-md, was 0.25rem */
            border: 1px solid #e5e7eb; /* Tailwind gray-200, was #eee */
        }}
        .compliance-standard-name {{
            font-weight: 600; /* Bolder */
            color: #1f2937; /* Tailwind gray-800, was #333 */
            display: block;
            margin-bottom: 0.6rem; /* More space */
        }}
        .compliance-chips-container {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.6rem; /* Slightly more gap */
        }}
        .chip.compliance-chip {{
            background-color: #e5e7eb; /* Tailwind gray-200, was #e0e0e0 */
            color: #374151; /* Tailwind gray-700, was #333 */
            padding: 0.3em 0.7em; /* Adjusted padding */
            font-size: 0.8em;
            border-radius: 0.375rem; /* Tailwind rounded-md */
        }}
        /* Remove old read-more styles */
        /* .show-read-more .more-text {{display: none;}} */

        /* Copy Icon Styles */
        .copy-icon {{
            margin-left: 8px;
            cursor: pointer;
            color: #6b7280; /* Tailwind gray-500 */
            font-size: 0.9em;
        }}
        .copy-icon:hover {{
            color: #1f2937; /* Tailwind gray-800 */
        }}
        .tooltip-copied {{
            position: absolute;
            background-color: #374151; /* Tailwind gray-700 */
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            z-index: 1080; /* Above modal content */
            opacity: 0;
            transition: opacity 0.2s;
            pointer-events: none; /* Don't interfere with clicks */
            white-space: nowrap; /* Ensure tooltip text stays on one line */
        }}

        /* Info Icon & Tooltip for Compliance */
        .info-icon-tooltip-container {{
            position: relative;
            display: inline-block;
            margin-left: 8px;
        }}
        .info-icon {{
            cursor: help;
            color: #6b7280; /* Tailwind gray-500 */
            font-size: 0.9em;
        }}
        .info-icon-tooltip {{
            visibility: hidden;
            width: 280px;
            background-color: #374151; /* Tailwind gray-700 */
            color: #fff;
            text-align: left; /* Changed from center for better readability */
            border-radius: 6px;
            padding: 8px 12px; /* Adjusted padding */
            position: absolute;
            z-index: 1081;
            top: 50%; /* For vertical centering */
            left: 100%; /* Position to the right of the container */
            transform: translateY(-50%); /* Adjust for vertical centering */
            margin-left: 10px; /* Space between icon and tooltip */
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 0.75rem;
            line-height: 1.4;
        }}
        .info-icon-tooltip::after {{ /* Tooltip arrow, pointing left */
            content: "";
            position: absolute;
            top: 50%;
            right: 100%; /* Arrow on the left side of the tooltip */
            margin-top: -5px; /* To vertically center the arrow */
            border-width: 5px;
            border-style: solid;
            border-color: transparent #374151 transparent transparent; /* Arrow color pointing left */
        }}
        .info-icon-tooltip-container:hover .info-icon-tooltip {{
            visibility: visible;
            opacity: 1;
        }}

        /* DataTables SearchPanes Button & Panel Styling */
        .dt-button.buttons-searchPanes {{
            background-color: #007bff;
            color: white;
            border: none;
            padding: 0.375rem 0.75rem;
            border-radius: 0.25rem;
            font-size: 0.875rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            transition: background-color 0.2s;
        }}
        .dt-button.buttons-searchPanes:hover {{
            background-color: #0056b3;
        }}

        /* DataTables SearchPanes Container Adjustments (for modal pop-up) */
        div.dtsp-searchPanes {{
            border-radius: 0.375rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        div.dtsp-panesContainer {{
            max-height: 400px;
            overflow-y: auto;
            padding: 0.5rem;
        }}
        div.dtsp-searchPane {{
            margin-bottom: 0.5rem;
        }}
        div.dtsp-topRow {{
            padding: 0.5rem 0.75rem;
            border-bottom: 1px solid #e5e7eb;
        }}
        div.dtsp-searchPane div.dataTables_scrollBody {{
            max-height: 200px !important;
        }}

        /* BEGIN: Inline DataTables SearchPanes Styling (REMOVING/COMMENTING THIS BLOCK) */
        /*
        div.dt-searchPanes {{ ... }}
        div.dtsp-panesContainer {{ ... }}
        ...
        */
        /* END: Inline DataTables SearchPanes Styling */

        /* BEGIN: Collapsible Filter Section Styling (REMOVING/COMMENTING THIS BLOCK) */
        /*
        #filtersCollapsibleSection {{ ... }}
        .filtersCollapsibleHeader {{ ... }}
        ...
        */
        /* END: Collapsible Filter Section Styling */

        /* DataTables Sort Icon Customization */
        #findingsTable.dataTable thead .sorting::after,
        #findingsTable.dataTable thead .sorting_asc::after,
        #findingsTable.dataTable thead .sorting_desc::after {{
            font-family: 'Font Awesome 5 Pro' !important;
            font-weight: 900 !important; /* Required for solid FA icons */
            font-size: 0.85em !important; /* Slightly smaller relative to header text */
            opacity: 0.5 !important; /* More subtle */
            position: absolute !important;
            right: 10px !important; /* Adjusted positioning */
            top: 50% !important;
            transform: translateY(-50%) !important;
            content: '' !important; /* Clear default content first */
        }}

        #findingsTable.dataTable thead .sorting::after {{
            content: '\\f0dc' !important;  /* fa-sort */
        }}
        #findingsTable.dataTable thead .sorting_asc::after {{
            content: '\\f0de' !important; /* fa-sort-up */
        }}
        #findingsTable.dataTable thead .sorting_desc::after {{
            content: '\\f0dd' !important; /* fa-sort-down */
        }}

        #findingsTable.dataTable thead .sorting::before,
        #findingsTable.dataTable thead .sorting_asc::before,
        #findingsTable.dataTable thead .sorting_desc::before {{
            display: none !important;
        }}

        /* Styling for DataTables Bottom Controls (Info, Pagination, Length) */
        div.dataTables_wrapper div.row:last-child {{ /* Target the row containing bottom controls */
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1rem 0.5rem; /* Increased padding for better spacing */
            border-top: 1px solid #dee2e6; /* Separator line */
            margin-top: 0; /* Remove negative margin */
            background-color: #f8f9fa; /* Light background for better visibility */
            border-radius: 0 0 0.375rem 0.375rem; /* Rounded bottom corners */
        }}
        .dataTables_info {{
            padding: 0.5rem 0; /* Better vertical padding */
            font-size: 0.875rem;
            color: #6c757d; /* Muted text color */
            flex-shrink: 0; /* Prevent shrinking */
        }}
        .dataTables_length {{
            display: flex !important;
            align-items: center !important;
            flex-shrink: 0; /* Prevent shrinking */
            gap: 0.5rem; /* Add consistent spacing between elements */
        }}
        .dataTables_length label {{
            display: flex !important;
            align-items: center !important;
            font-size: 0.875rem !important;
            margin: 0 !important; /* Remove default margin */
            color: #6c757d !important; /* Muted text color */
            white-space: nowrap !important; /* Prevent text wrapping */
            gap: 0 !important; /* Remove gap, we'll handle spacing manually */
        }}
        .dataTables_length select {{
            padding: 0.375rem 0.75rem !important;
            border-radius: 0.25rem !important;
            border: 1px solid #ced4da !important;
            background-color: #fff !important;
            font-size: 0.875rem !important;
            min-width: 80px !important; /* Give it some base width */
            height: auto !important; /* Ensure proper height */
            line-height: 1.5 !important; /* Match text line height */
            margin: 0 0.5rem !important; /* Manual spacing around select */
            vertical-align: middle !important;
        }}
        /* Override DataTables default spacing */
        .dataTables_length label > * {{
            vertical-align: middle !important;
        }}
        /* Force inline layout for length control text nodes */
        .dataTables_length label {{
            font-size: 0.875rem !important;
            line-height: 1.5 !important;
        }}
        /* Additional specific targeting for DataTables length control */
        div.dataTables_length {{
            min-height: 38px !important;
            display: flex !important;
            align-items: center !important;
        }}
        div.dataTables_length label {{
            display: inline-flex !important;
            align-items: center !important;
            vertical-align: middle !important;
            margin-bottom: 0 !important;
            padding: 0 !important;
        }}
        /* Target text nodes specifically */
        .dataTables_length label::before {{
            content: "Show" !important;
            margin-right: 0.5rem !important;
        }}
        .dataTables_length label::after {{
            content: "entries" !important;
            margin-left: 0.5rem !important;
        }}
        /* Hide original text nodes */
        .dataTables_length label {{
            font-size: 0 !important;
        }}
        .dataTables_length label select {{
            font-size: 0.875rem !important;
        }}
        .dataTables_paginate {{
            display: flex;
            align-items: center;
            flex-shrink: 0; /* Prevent shrinking */
        }}
        .dataTables_paginate .paginate_button {{
            padding: 0.4em 0.8em; /* Adjust padding for a better look */
            margin-left: 2px;
            border-radius: 0.25rem !important; /* Ensure our radius is applied */
        }}
        .dataTables_paginate .paginate_button.current,
        .dataTables_paginate .paginate_button.current:hover {{
            background: #007bff !important;
            color: white !important;
            border-color: #007bff !important;
        }}
        .dataTables_paginate .paginate_button:hover {{
            background: #e9ecef !important;
            border-color: #dee2e6 !important;
            color: #007bff !important;
        }}

        /* Dark Theme Styles */
        body.dark-theme {{
            background-color: #1a1a1a; /* Dark background */
            color: #e0e0e0; /* Light text */
        }}
        body.dark-theme .card {{
            background-color: #2c2c2c; /* Darker card background */
            border: 1px solid #444; /* Darker border */
            box-shadow: 0 4px 6px -1px rgba(0,0,0,.2), 0 2px 4px -2px rgba(0,0,0,.15);
        }}
        body.dark-theme .card-header {{
            background-color: #383838; /* Dark card header */
            color: #f0f0f0; /* Light header text */
            border-bottom: 1px solid #444;
        }}
        body.dark-theme .card .list-group-item {{
            background-color: #2c2c2c;
            color: #e0e0e0;
            border-bottom: 1px solid #383838;
        }}
        body.dark-theme .card .list-group-item:last-child {{
            border-bottom: none;
        }}
        body.dark-theme .card .list-group-item b {{
            color: #f0f0f0;
        }}
        body.dark-theme #assessmentOverviewCard .list-group-item span.value {{
            color: #f5f5f5;
        }}
        body.dark-theme .overview-bar-container {{
            background-color: #444; /* Darker track for overview bar */
        }}
        body.dark-theme .table-responsive-container {{
            border: 1px solid #444;
            box-shadow: 0 0.125rem 0.35rem rgba(0,0,0,.15);
        }}
        body.dark-theme #findingsTable {{
            /* No specific change needed if row/cell backgrounds are handled by hover/status */
        }}
        body.dark-theme #findingsTable th,
        body.dark-theme #findingsTable td {{
            border-bottom: 1px solid #444; /* Darker row separation */
        }}
        body.dark-theme #findingsTable thead th {{
            background-color: #333 !important; /* Darker table header */
            color: #e0e0e0 !important;
            border-bottom: 1px solid #555 !important;
        }}
        body.dark-theme #findingsTable tbody tr:hover {{
            background-color: #383838; /* Darker hover for table rows */
        }}
        body.dark-theme #findingsTable td {{
            color: #c0c0c0; /* Lighter text for table cells */
        }}
        body.dark-theme .chip {{
            /* Chips may need specific adjustments based on their light theme contrast */
        }}
        body.dark-theme .status-chip.status-table-danger {{ background-color: #58181F; color: #F8D7DA; }}
        body.dark-theme .status-chip.status-table-success {{ background-color: #155724; color: #D4EDDA; }} /* Already dark bg friendly */
        body.dark-theme .status-chip.status-table-info {{ background-color: #0C5460; color: #D1ECF1; }} /* Already dark bg friendly */
        body.dark-theme .status-chip.status-table-warning {{ background-color: #665100; color: #FFF3CD; }}
        body.dark-theme .severity-chip.severity-critical {{ background-color: #dc3545; color: white; }} /* Stays same, good contrast */
        body.dark-theme .severity-chip.severity-high {{ background-color: #fd7e14; color: white; }} /* Stays same */
        body.dark-theme .severity-chip.severity-medium {{ background-color: #ffc107; color: #212529; }} /* Stays same */
        body.dark-theme .severity-chip.severity-low {{ background-color: #28a745; color: white; }} /* Stays same */
        body.dark-theme .severity-chip.severity-informational {{ background-color: #17a2b8; color: white; }} /* Stays same */
        body.dark-theme .service-chip {{
            background-color: #5a6268; /* Darker gray for service chip */
            color: white;
        }}
        body.dark-theme .prowler-modal-content {{
            background-color: #2c2c2c;
            box-shadow: 0 10px 15px -3px rgba(0,0,0,0.3), 0 4px 6px -2px rgba(0,0,0,0.2);
            border: 1px solid #444;
        }}
        body.dark-theme .prowler-modal-header {{
            border-bottom: 1px solid #444;
        }}
        body.dark-theme .prowler-modal-title {{
            color: #f0f0f0;
        }}
        body.dark-theme .prowler-modal-close-btn {{
            color: #aaa;
        }}
        body.dark-theme .prowler-modal-close-btn:hover {{
            color: #f0f0f0;
        }}
        body.dark-theme .prowler-modal-body {{
            color: #e0e0e0;
        }}
        body.dark-theme .prowler-modal-section h4 {{
            color: #f5f5f5;
        }}
        body.dark-theme .prowler-modal-section-header {{
            border-bottom: 1px solid #444;
        }}
        body.dark-theme .prowler-modal-section-header:hover {{
            background-color: #383838;
        }}
        body.dark-theme .prowler-modal-section-toggle {{
            color: #aaa;
        }}
        body.dark-theme .prowler-modal-section-content {{
            background-color: #383838;
            border: 1px solid #444;
            border-top: none;
        }}
        body.dark-theme .prowler-modal-section-content.fail-highlight {{
            background-color: #4d3232; /* Darker red highlight */
            border-color: #6e4949;
        }}
        body.dark-theme .prowler-modal-label {{
            color: #b0b0b0;
        }}
        body.dark-theme .prowler-modal-value {{
            color: #e0e0e0;
        }}
        body.dark-theme .prowler-modal-value a {{
            color: #6bbaff;
        }}
        body.dark-theme .prowler-modal-value code, body.dark-theme .prowler-modal-value pre {{
            background-color: #333;
            color: #d0d0d0;
        }}
        body.dark-theme .modal-header-chips {{
            border-bottom: 1px solid #444;
        }}
        body.dark-theme .modal-header-chips .chip-label {{
            color: #b0b0b0;
        }}
        body.dark-theme .modal-header-chips .chip {{
            /* Chips might need specific color adjustments for dark theme if not covered by general chip rules */
        }}
        body.dark-theme .compliance-standard-item {{
            background-color: #383838;
            border: 1px solid #444;
        }}
        body.dark-theme .compliance-standard-name {{
            color: #f0f0f0;
        }}
        body.dark-theme .chip.compliance-chip {{
            background-color: #4a4a4a;
            color: #e0e0e0;
        }}
        body.dark-theme .copy-icon {{
            color: #aaa;
        }}
        body.dark-theme .copy-icon:hover {{
            color: #f0f0f0;
        }}
        body.dark-theme .tooltip-copied {{
            background-color: #f0f0f0;
            color: #1a1a1a;
        }}
        body.dark-theme .info-icon {{
            color: #aaa;
        }}
        body.dark-theme .info-icon-tooltip {{
            background-color: #f0f0f0;
            color: #1a1a1a;
        }}
        body.dark-theme .info-icon-tooltip::after {{
             border-color: transparent #f0f0f0 transparent transparent;
        }}
        body.dark-theme div.dataTables_wrapper div.row:last-child {{
            border-top: 1px solid #444;
            background-color: #2c2c2c; /* Dark background for pagination area */
        }}
        body.dark-theme .dataTables_info {{
            color: #b0b0b0;
        }}
        body.dark-theme .dataTables_length label {{
            color: #b0b0b0;
        }}
        body.dark-theme .dataTables_length select {{
            background-color: #333;
            color: #e0e0e0;
            border: 1px solid #555;
        }}
        body.dark-theme .dataTables_paginate .paginate_button {{
            /* Handled by Bootstrap's default, check if override needed */
            color: #e0e0e0 !important;
            border: 1px solid transparent; /* To match light theme structure */
        }}
        body.dark-theme .dataTables_paginate .paginate_button.disabled,
        body.dark-theme .dataTables_paginate .paginate_button.disabled:hover {{
            color: #666 !important;
            background: transparent !important; /* Ensure disabled has no distracting bg */
            border-color: transparent !important;
        }}

        body.dark-theme .dataTables_paginate .paginate_button.current,
        body.dark-theme .dataTables_paginate .paginate_button.current:hover {{
            background: #0056b3 !important; /* Darker blue for current page in dark mode */
            color: white !important;
            border-color: #0056b3 !important;
        }}
        body.dark-theme .dataTables_paginate .paginate_button:hover {{
            background: #4a4a4a !important;
            border-color: #555 !important;
            color: #e0e0e0 !important;
        }}
         /* Theme Switcher Styles */
        .theme-switcher-container {{
            position: absolute;
            top: 20px;
            right: 20px;
            display: flex;
            align-items: center;
        }}
        .theme-switch-label {{
            margin-right: 8px;
            font-size: 0.8rem;
            color: #4b5563; /* Default for light theme */
        }}
        body.dark-theme .theme-switch-label {{
            color: #b0b0b0; /* For dark theme */
        }}
        .theme-switch {{
            position: relative;
            display: inline-block;
            width: 50px; /* Adjusted width */
            height: 26px; /* Adjusted height */
        }}
        .theme-switch input {{
            opacity: 0;
            width: 0;
            height: 0;
        }}
        .slider {{
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .4s;
            border-radius: 26px; /* Keep it rounded */
        }}
        .slider:before {{
            position: absolute;
            content: "";
            height: 20px; /* Smaller circle */
            width: 20px;  /* Smaller circle */
            left: 3px;    /* Adjusted position */
            bottom: 3px;  /* Adjusted position */
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }}
        input:checked + .slider {{
            background-color: #007bff; /* Blue for dark mode enabled */
        }}
        input:focus + .slider {{
            box-shadow: 0 0 1px #007bff;
        }}
        input:checked + .slider:before {{
            transform: translateX(24px); /* Adjusted translation */
        }}
        /* End Theme Switcher Styles */

        /* Chart Styles */
        .card canvas {{
            background-color: transparent;
        }}

        /* Dark theme chart adjustments */
        body.dark-theme canvas {{
            filter: brightness(0.9);
        }}

        /* Ensure proper vertical alignment for all DataTables controls */
        .dataTables_wrapper .row {{
            align-items: center;
        }}
        .dataTables_wrapper .col-sm-12.col-md-6 {{
            display: flex;
            align-items: center;
        }}
        /* Fix for DataTables responsive layout */
        @media (max-width: 767px) {{
            div.dataTables_wrapper div.row:last-child {{
                flex-direction: column;
                gap: 1rem;
                align-items: flex-start;
            }}
            .dataTables_length,
            .dataTables_info,
            .dataTables_paginate {{
                width: 100%;
                justify-content: center;
            }}
        }}
    </style>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css"
        integrity="sha384-9aIt2nRpC12Uk9gS9baDl411NQApFmC26EwAOH8WgZl5MYYxFfc+NcPb1dKGj7Sk" crossorigin="anonymous" />
    <!-- https://datatables.net/download/index with jQuery, DataTables, Buttons, SearchPanes, and Select //-->
    <link rel="stylesheet" type="text/css"
        href="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.25/b-1.7.1/sp-1.4.0/sl-1.3.3/datatables.min.css" />
    <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.10.0/css/all.css"
        integrity="sha384-AYmEC3Yw5cVb3ZcuHtOA93w35dYTsvhLPVnYs9eStHfGJvOvKxVfELGroGkvsg+p" crossorigin="anonymous" />
    <style>
        .show-read-more .more-text {{display: none;}}

        .dataTable {{font-size: 14px;}}

        .container-fluid {{font-size: 14px;}}

        .float-left {{ float: left !important; max-width: 100%; }}
    </style>
    <title>Prowler - The Handy Cloud Security Tool</title>
    </head>
    <body>
    <div class="theme-switcher-container">
        <span class="theme-switch-label">Dark Mode:</span>
        <label class="theme-switch">
            <input type="checkbox" id="themeToggleCheckbox">
            <span class="slider"></span>
        </label>
    </div>
    <div class="container-fluid">
        <div class="row mt-3 align-items-stretch">
        <div class="col-md-4">
            <a href="{html_logo_url}"><img class="float-left card-img-left mt-2 mr-4 ml-4"
                        src={square_logo_img}
                        alt="prowler-logo"
                        style="width: 15rem; height:auto;"/></a>
            <div class="card" id="reportInfoCard">
            <div class="card-header">
                Report Information
            </div>
            <ul class="list-group list-group-flush">
                <li class="list-group-item">
                <div class="row">
                    <div class="col-md-auto">
                    <b>Version:</b> {prowler_version}
                    </div>
                </div>
                </li>
                <li class="list-group-item">
                <b>Parameters used:</b> {" ".join(sys.argv[1:]) if from_cli else ""}
                </li>
                <li class="list-group-item">
                <b>Date:</b> {timestamp.isoformat()}
                </li>
            </ul>
            </div>
        </div>{HTML.get_assessment_summary(provider)}
            <div class="col-md-2">
            <div class="card" id="assessmentOverviewCard">
                <div class="card-header">
                    Assessment Overview
                </div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item">
                        <b>Total Findings:</b> <span class="value">{str(stats.get("findings_count", 0))}</span>
                    </li>
                    {HTML._generate_overview_bar_list_item(stats, "total_pass", "Passed", "overview-bar-passed")}
                    <li class="list-group-item">
                        <b>Passed (Muted):</b> <span class="value">{str(stats.get("total_muted_pass", 0))}</span>
                    </li>
                    {HTML._generate_overview_bar_list_item(stats, "total_fail", "Failed", "overview-bar-failed")}
                    <li class="list-group-item">
                        <b>Failed (Muted):</b> <span class="value">{str(stats.get("total_muted_fail", 0))}</span>
                    </li>
                    <li class="list-group-item">
                        <b>Total Resources:</b> <span class="value">{str(stats.get("resources_count", 0))}</span>
                    </li>
                </ul>
            </div>
        </div>
        </div>
        </div>
        <div class="row-mt-3">
        <div class="col-md-12">
            <div class="table-responsive-container">
            <table class="table compact stripe row-border ordering" id="findingsTable" data-order='[[0, "asc"], [1, "asc"]]' data-page-length='100'>
            <thead class="thead-light">
                <tr>
                    <th scope="col">Status</th>
                    <th scope="col">Severity</th>
                    <th scope="col">Service Name</th>
                    <th scope="col">Region</th>
                    <th style="width:20%" scope="col">Check ID</th>
                    <th scope="col">Resource ID</th>
                    <th scope="col">Resource Type</th>
                </tr>
            </thead>
            <tbody>"""
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def _generate_overview_bar_list_item(
        stats: dict, stat_key: str, label: str, bar_class: str
    ) -> str:
        total_findings = stats.get("findings_count", 0)
        count = stats.get(stat_key, 0)
        percentage = (count / total_findings * 100) if total_findings > 0 else 0
        return f"""
            <li class="list-group-item">
                <b>{label}:</b>
                <div class="overview-bar-container">
                    <span class="overview-bar {bar_class}" style="width: {percentage}%;"></span>
                </div>
                <span class="value">{str(count)}</span>
            </li>
        """

    @staticmethod
    def write_footer(file_descriptor: TextIOWrapper) -> None:
        """
        Writes the footer of the HTML file.

        Args:
            file_descriptor (file): the file descriptor to write the footer
        """
        try:
            file_descriptor.write(
                """
            </tbody>
            </table>
        </div>
    </div>
    <!-- Finding Detail Modal HTML -->
    <div id="findingModal" class="prowler-modal-backdrop">
      <div class="prowler-modal-content">
        <div class="prowler-modal-header">
          <h3 id="modalTitle" class="prowler-modal-title">Finding Details</h3>
          <button id="modalCloseBtn" class="prowler-modal-close-btn">&times;</button>
        </div>
        <div id="modalBody" class="prowler-modal-body">
          <!-- Content will be injected by JavaScript -->
        </div>
      </div>
    </div>

    <!-- Table search and paginator -->
    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.5.1.min.js"
        integrity="sha256-9/aliU8dGd2tb6OSsuzixeV4y/faTqgFtohetphbbj0=" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/js/bootstrap.bundle.min.js"
        integrity="sha384-1CmrxMRARb6aLqgBO7yyAxTOQE2AKb9GfXnEo760AUcUmFx3ibVJJAzGytlQcNXd"
        crossorigin="anonymous"></script>
    <!-- https://datatables.net/download/index with jQuery, DataTables, Buttons, SearchPanes, and Select //-->
    <script type="text/javascript"
        src="https://cdn.datatables.net/v/dt/jqc-1.12.4/dt-1.10.25/b-1.7.1/sp-1.4.0/sl-1.3.3/datatables.min.js"></script>
    <script>
        $(document).ready(function () {
            // Initialise the table with 50 rows, and some search/filtering panes
            var findingsDataTable = $('#findingsTable').DataTable({ // Store table instance
                responsive: true,
                // Show 25, 50, 100 and All records
                lengthChange: true,
                lengthMenu: [[25, 50, 100, -1], [25, 50, 100, "All"]],
                searchPanes: {
                    cascadePanes: true, // Keep this from previous successful state
                    viewTotal: true,
                    layout: 'columns-3' // Keep this for the button pop-up for now
                },
                dom: 'Bfrtipl', // B=Buttons, f=filtering input, r=processing, t=table, i=info, p=pagination, l=length changing
                language: {
                    searchPanes: {
                        clearMessage: 'Clear Filters',
                        collapse: { 0: 'Filters', _: 'Filters (%d)' },
                        initCollapsed: true // For the button state
                    }
                },
                buttons: [
                    {
                        extend: 'searchPanes',
                        config: {
                            cascadePanes: true,
                            viewTotal: true,
                            orderable: false
                            // layout: 'columns-3' // Can also be set here if needed
                        }
                    }
                ],
                columnDefs: [
                    {
                        searchPanes: {
                            show: true,
                            pagingType: 'numbers',
                            searching: true,
                            orthogonal: 'filter'
                        },
                        // Filters for: Status, Severity, ServiceName, Region, CheckID, ResourceType
                        targets: [0, 1, 2, 3, 4, 6]
                    }
                ]
            });

            // Fix DataTables length control alignment
            setTimeout(function() {
                // Force proper styling on the length control
                $('.dataTables_length').css({
                    'display': 'flex',
                    'align-items': 'center',
                    'gap': '0.5rem'
                });

                $('.dataTables_length label').css({
                    'display': 'flex',
                    'align-items': 'center',
                    'margin': '0',
                    'gap': '0.5rem'
                });

                // Ensure select has proper margins
                $('.dataTables_length select').css({
                    'margin': '0',
                    'vertical-align': 'middle'
                });
            }, 100); // Small delay to ensure DataTables has finished rendering

            // BEGIN: Collapsible Filters Logic (REMOVING THIS BLOCK)
            /*
            const filtersCollapsibleHeader = document.querySelector('.filtersCollapsibleHeader');
            const filtersCollapsibleContent = document.querySelector('.filtersCollapsibleContent');
            const dtSearchPanesElement = document.querySelector('div.dt-searchPanes');

            if (dtSearchPanesElement && filtersCollapsibleContent) {
                filtersCollapsibleContent.appendChild(dtSearchPanesElement);
            }

            if (filtersCollapsibleHeader) {
                filtersCollapsibleHeader.addEventListener('click', function() {
                    this.classList.toggle('expanded');
                    if (filtersCollapsibleContent) {
                        filtersCollapsibleContent.classList.toggle('expanded');
                    }
                });
            }
            */
            // END: Collapsible Filters Logic

            // Modal elements
            const modal = document.getElementById('findingModal');
            const modalTitleEl = document.getElementById('modalTitle');
            const modalBodyEl = document.getElementById('modalBody');
            const modalCloseBtn = document.getElementById('modalCloseBtn');

            let copyTimeout = null; // For hiding tooltip

            function showCopiedTooltip(targetElement) {
                let tooltip = document.getElementById('copyTooltip');
                if (!tooltip) {
                    tooltip = document.createElement('div');
                    tooltip.id = 'copyTooltip';
                    tooltip.className = 'tooltip-copied';
                    document.body.appendChild(tooltip);
                }
                tooltip.textContent = 'Copied!';

                const rect = targetElement.getBoundingClientRect();
                // Position to the right of the icon, vertically centered
                tooltip.style.left = `${rect.right + 8}px`; // 8px offset from the icon
                tooltip.style.top = `${rect.top + (rect.height / 2) - (tooltip.offsetHeight / 2)}px`;

                tooltip.style.opacity = '1';

                clearTimeout(copyTimeout);
                copyTimeout = setTimeout(() => {
                    tooltip.style.opacity = '0';
                }, 1500);
            }

            function addCopyIcon(textToCopy, isRawText = true) {
                // For raw text, it might contain HTML entities if it was from an attribute.
                // We need to decode them before copying for accurate clipboard content.
                let decodedText = textToCopy;
                if (isRawText && typeof textToCopy === 'string') {
                    const textarea = document.createElement('textarea');
                    textarea.innerHTML = textToCopy;
                    decodedText = textarea.value;
                }
                return `<span class="copy-icon" data-copy-text="${escapeHtml(decodedText)}" title="Copy to clipboard"><i class="fas fa-copy"></i></span>`;
            }

            function formatRawDataForDisplay(rawData, isJson = true, dataType = 'generic') {
                if (!rawData || rawData === '{}' || rawData === 'null') return '<span style="color: #6c757d;">Not Available</span>';

                try {
                    const data = isJson ? JSON.parse(rawData) : rawData;

                    if (dataType === 'compliance' && typeof data === 'object' && data !== null) {
                        if (Object.keys(data).length === 0) return '<span style="color: #6c757d;">No compliance data.</span>';
                        let complianceHtml = '';
                        for (const standardKey in data) {
                            complianceHtml += `<div class="compliance-standard-item">`;
                            complianceHtml += `<span class="compliance-standard-name">${escapeHtml(standardKey)}</span>`;
                            const standardData = data[standardKey];
                            let requirements = [];

                            if (standardData && standardData.Sections && Array.isArray(standardData.Sections)) {
                                requirements = standardData.Sections.map(s => s.Name).filter(Boolean);
                            } else if (standardData && standardData.Requirements && Array.isArray(standardData.Requirements)) {
                                requirements = standardData.Requirements.map(r => r.Id || r.Name || r.ControlID).filter(Boolean);
                            } else if (Array.isArray(standardData)) { // Handles simpler arrays of strings if that's the format
                                requirements = standardData.map(s => String(s));
                            } else if (typeof standardData === 'string') { // If the value is just a string
                                requirements = [standardData];
                            }
                            // Add other potential structures from Prowler's compliance objects as needed

                            if (requirements.length > 0) {
                                complianceHtml += `<div class="compliance-chips-container">`;
                                requirements.forEach(req => {
                                    complianceHtml += `<span class="chip compliance-chip">${escapeHtml(req)}</span>`;
                                });
                                complianceHtml += `</div>`;
                            } else {
                                complianceHtml += `<div class="compliance-chips-container"><span style="color: #6c757d; font-style: italic;">No specific requirements listed.</span></div>`;
                            }
                            complianceHtml += `</div>`;
                        }
                        return complianceHtml;
                    }

                    // Resource Tags display using chips
                    if (dataType === 'tags' && typeof data === 'object' && data !== null) {
                        if (Object.keys(data).length === 0) return '<span style="color: #6c757d;">No tags.</span>';
                        let tagsHtml = '<div class="compliance-chips-container" style="padding-top: 5px;">'; // Re-use compliance-chips-container for styling
                        for (const key in data) {
                            tagsHtml += `<span class="chip compliance-chip">${escapeHtml(key)}: ${escapeHtml(String(data[key]))}</span>`;
                        }
                        tagsHtml += '</div>';
                        return tagsHtml;
                    }

                    // Generic JSON or string formatting
                    if (typeof data === 'object' && data !== null) {
                        if (Object.keys(data).length === 0) return '<span style="color: #6c757d;">Empty</span>';
                        let html = '<ul>';
                        for (const key in data) {
                            let value = data[key];
                            if (typeof value === 'object' && value !== null) {
                                value = JSON.stringify(value, null, 2);
                                html += `<li><strong>${escapeHtml(key)}:</strong> <pre><code>${escapeHtml(value)}</code></pre></li>`;
                            } else {
                                html += `<li><strong>${escapeHtml(key)}:</strong> ${escapeHtml(String(value))}</li>`;
                            }
                        }
                        html += '</ul>';
                        return html;
                    } else {
                        return escapeHtml(String(data));
                    }
                } catch (e) {
                    return escapeHtml(String(rawData));
                }
            }

            function escapeHtml(unsafe) {
                if (unsafe === null || typeof unsafe === 'undefined') return '';
                return String(unsafe)
                     .replace(/&/g, "&amp;")
                     .replace(/</g, "&lt;")
                     .replace(/>/g, "&gt;")
                     .replace(/"/g, "&quot;")
                     .replace(/'/g, "&#039;");
            }

            // Handle row click to open modal
            $('#findingsTable tbody').on('click', 'tr', function () {
              try {
                const row = $(this); // jQuery object for the clicked <tr>
                const data = findingsDataTable.row(this).data();

                if (!data) {
                    console.error("DataTables row data is undefined for the clicked row.", this);
                    // If data is crucial for some fallback or unhandled part, return.
                    // However, we aim to get most visual data from `row` or `data-*` attributes.
                    // return;
                }

                // Extract data from data-* attributes for raw/full content
                const riskRaw = row.attr('data-risk-raw');
                const statusExtendedRaw = row.attr('data-status-extended-raw');
                const remediationTextRaw = row.attr('data-remediation-text-raw');
                const remediationUrl = row.attr('data-remediation-url');
                const descriptionRaw = row.attr('data-description-raw');
                const rawCheckId = row.attr('data-check-id-raw');
                const resourceTagsRaw = row.attr('data-resource-tags-raw');
                const complianceRaw = row.attr('data-compliance-raw');

                // HTML content from table cells for modal header chips
                const statusCellHtml = row.find('td:eq(0)').html() || '<span class="chip status-chip">Unknown</span>';
                const severityCellHtml = row.find('td:eq(1)').html() || '<span class="chip severity-chip">Unknown</span>';
                const serviceNameCellHtml = row.find('td:eq(2)').html() || '<span class="chip service-chip">Unknown</span>';

                // Text/HTML content from table cells for other parts of the modal display
                const regionText = row.find('td:eq(3)').text();
                const checkIdLinkHtml = row.find('td:eq(4)').html();
                const resourceIdText = row.find('td:eq(5)').text(); // Adjusted index after column removal

                modalTitleEl.textContent = rawCheckId || 'Finding Details';

                let modalContentHtml = '<div class="modal-header-chips">';
                modalContentHtml += `<div class="chip-item"><span class="chip-label">Status:</span>${statusCellHtml}</div>`;
                modalContentHtml += `<div class="chip-item"><span class="chip-label">Severity:</span>${severityCellHtml}</div>`;
                modalContentHtml += `<div class="chip-item"><span class="chip-label">Service:</span>${serviceNameCellHtml}</div>`;
                modalContentHtml += `<div class="chip-item"><span class="chip-label">Region:</span><span class="chip" style="background-color: #e9ecef; color: #495057;">${escapeHtml(regionText)}</span></div>`;
                modalContentHtml += '</div>';

                // Section 1: Finding Information
                modalContentHtml += '<div class="prowler-modal-section">';
                modalContentHtml += '  <div class="prowler-modal-section-header">';
                modalContentHtml += '    <h4>Finding Information</h4>';
                modalContentHtml += '    <span class="prowler-modal-section-toggle">&#9660;</span>';
                modalContentHtml += '  </div>';
                modalContentHtml += '  <div class="prowler-modal-section-content">';
                modalContentHtml += `    <div class="prowler-modal-row"><span class="prowler-modal-label">Check ID:</span><span class="prowler-modal-value">${checkIdLinkHtml}${addCopyIcon(rawCheckId, true)}</span></div>`;
                modalContentHtml += `    <div class="prowler-modal-row"><span class="prowler-modal-label">Description:</span><span class="prowler-modal-value">${formatRawDataForDisplay(descriptionRaw, false)}</span></div>`;
                modalContentHtml += `    <div class="prowler-modal-row"><span class="prowler-modal-label">Status Extended:</span><span class="prowler-modal-value">${formatRawDataForDisplay(statusExtendedRaw, false)}${addCopyIcon(statusExtendedRaw, true)}</span></div>`;
                modalContentHtml += '  </div>';
                modalContentHtml += '</div>';

                // Section 2: Resource Details
                modalContentHtml += '<div class="prowler-modal-section">';
                modalContentHtml += '  <div class="prowler-modal-section-header">';
                modalContentHtml += '    <h4>Resource Details</h4>';
                modalContentHtml += '    <span class="prowler-modal-section-toggle">&#9660;</span>';
                modalContentHtml += '  </div>';
                modalContentHtml += '  <div class="prowler-modal-section-content">';
                modalContentHtml += `    <div class="prowler-modal-row"><span class="prowler-modal-label">ID:</span><span class="prowler-modal-value">${escapeHtml(resourceIdText)}${addCopyIcon(resourceIdText, false)}</span></div>`;
                modalContentHtml += `    <div class="prowler-modal-row"><span class="prowler-modal-label">Tags:</span><span class="prowler-modal-value">${formatRawDataForDisplay(resourceTagsRaw, true, 'tags')}</span></div>`;
                modalContentHtml += '  </div>';
                modalContentHtml += '</div>';

                // Section 3: Risk & Remediation
                let isFail = false;
                if (statusCellHtml && typeof statusCellHtml === 'string') {
                    // Check for the class that indicates a FAIL status directly in the HTML of the status chip
                    isFail = statusCellHtml.includes('status-table-danger');
                }
                const riskSectionClass = isFail ? 'prowler-modal-section-content fail-highlight' : 'prowler-modal-section-content';

                modalContentHtml += '<div class="prowler-modal-section">';
                modalContentHtml += '  <div class="prowler-modal-section-header">';
                modalContentHtml += '    <h4>Risk & Remediation</h4>';
                modalContentHtml += '    <span class="prowler-modal-section-toggle">&#9660;</span>';
                modalContentHtml += '  </div>';
                modalContentHtml += `  <div class="${riskSectionClass}">`;
                modalContentHtml += `    <div class="prowler-modal-row"><span class="prowler-modal-label" style="font-weight: 500;">Risk:</span><span class="prowler-modal-value">${formatRawDataForDisplay(riskRaw, false)}</span></div>`;
                let remediationDisplay = formatRawDataForDisplay(remediationTextRaw, false);
                if (remediationUrl && remediationUrl !== "N/A" && remediationUrl !== "") {
                    remediationDisplay += ` <a href="${escapeHtml(remediationUrl)}" target="_blank" rel="noopener noreferrer">(Learn more <i class="fas fa-external-link-alt"></i>)</a>`;
                }
                modalContentHtml += `    <div class="prowler-modal-row"><span class="prowler-modal-label" style="font-weight: 500;">Remediation:</span><span class="prowler-modal-value">${remediationDisplay}</span></div>`;
                modalContentHtml += '  </div>';
                modalContentHtml += '</div>';

                // Section 4: Compliance Details
                const complianceTooltipText = "Compliance information below shows the Framework/Standard and the specific Requirements or Sections related to this finding.";
                modalContentHtml += '<div class="prowler-modal-section">';
                modalContentHtml += '  <div class="prowler-modal-section-header">';
                modalContentHtml += '    <h4>Compliance Details <span class="info-icon-tooltip-container"><i class="fas fa-info-circle info-icon"></i><span class="info-icon-tooltip">' + escapeHtml(complianceTooltipText) + '</span></span></h4>';
                modalContentHtml += '    <span class="prowler-modal-section-toggle">&#9660;</span>';
                modalContentHtml += '  </div>';
                modalContentHtml += '  <div class="prowler-modal-section-content">';
                modalContentHtml += `    <div class="prowler-modal-row"><span class="prowler-modal-value">${formatRawDataForDisplay(complianceRaw, true, 'compliance')}</span></div>`;
                modalContentHtml += '  </div>';
                modalContentHtml += '</div>';

                modalBodyEl.innerHTML = modalContentHtml;
                modal.classList.add('visible');

                // Add event listeners for copy icons
                modalBodyEl.querySelectorAll('.copy-icon').forEach(icon => {
                    icon.addEventListener('click', (event) => {
                        event.stopPropagation();
                        const textToCopy = icon.dataset.copyText;
                        navigator.clipboard.writeText(textToCopy).then(() => {
                            showCopiedTooltip(icon);
                        }).catch(err => {
                            console.error('Failed to copy text: ', err);
                        });
                    });
                });

                // Add event listeners for collapsible sections
                modalBodyEl.querySelectorAll('.prowler-modal-section-header').forEach(header => {
                    header.addEventListener('click', () => {
                        const content = header.nextElementSibling;
                        const toggleIcon = header.querySelector('.prowler-modal-section-toggle');
                        content.classList.toggle('collapsed');
                        toggleIcon.classList.toggle('collapsed');
                        if (content.classList.contains('collapsed')) {
                            toggleIcon.innerHTML = '&#9654;';
                        } else {
                            toggleIcon.innerHTML = '&#9660;';
                        }
                    });
                });
              } catch (error) {
                console.error("Error in modal row click handler:", error);
                // Optionally, display a user-friendly error message in the modal or an alert
                if (modalTitleEl) modalTitleEl.textContent = 'Error';
                if (modalBodyEl) modalBodyEl.innerHTML = '<p>Sorry, an error occurred while trying to display the finding details. Please check the browser console for more information.</p>';
                if (modal && !modal.classList.contains('visible')) modal.classList.add('visible'); // Ensure modal is visible to show error
              }
            });

            // Close modal events
            modalCloseBtn.addEventListener('click', () => {
                modal.classList.remove('visible');
            });

            modal.addEventListener('click', (event) => {
                if (event.target === modal) { // Clicked on backdrop
                    modal.classList.remove('visible');
                }
            });

            // Close with Esc key
            document.addEventListener('keydown', (event) => {
                if (event.key === 'Escape' && modal.classList.contains('visible')) {
                    modal.classList.remove('visible');
                }
            });

            // Theme Switcher Logic
            const themeToggleCheckbox = document.getElementById('themeToggleCheckbox');
            const currentTheme = localStorage.getItem('theme');

            function applyTheme(theme) {
                if (theme === 'dark') {
                    document.body.classList.add('dark-theme');
                    themeToggleCheckbox.checked = true;
                } else {
                    document.body.classList.remove('dark-theme');
                    themeToggleCheckbox.checked = false;
                }
            }

            if (currentTheme) {
                applyTheme(currentTheme);
            } else {
                // Default to light theme if no preference is stored
                applyTheme('light');
            }

            themeToggleCheckbox.addEventListener('change', function() {
                if (this.checked) {
                    localStorage.setItem('theme', 'dark');
                    applyTheme('dark');
                } else {
                    localStorage.setItem('theme', 'light');
                    applyTheme('light');
                }
            });
        });
    </script>
</body>

</html>
"""
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )

    @staticmethod
    def get_aws_assessment_summary(provider: Provider) -> str:
        """
        get_aws_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            profile = (
                provider.identity.profile
                if provider.identity.profile is not None
                else "default"
            )
            if isinstance(provider.identity.audited_regions, list):
                audited_regions = " ".join(provider.identity.audited_regions)
            elif not provider.identity.audited_regions:
                audited_regions = "All Regions"
            else:
                audited_regions = ", ".join(provider.identity.audited_regions)
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            AWS Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>AWS Account:</b> {provider.identity.account}
                            </li>
                            <li class="list-group-item">
                                <b>AWS-CLI Profile:</b> {profile}
                            </li>
                            <li class="list-group-item">
                                <b>Audited Regions:</b> {audited_regions}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        AWS Credentials
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>User Id:</b> {provider.identity.user_id}
                            </li>
                            <li class="list-group-item">
                                <b>Caller Identity ARN:</b> {provider.identity.identity_arn}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_azure_assessment_summary(provider: Provider) -> str:
        """
        get_azure_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            printed_subscriptions = []
            for key, value in provider.identity.subscriptions.items():
                intermediate = f"{key} : {value}"
                printed_subscriptions.append(intermediate)

            # check if identity is str(coming from SP) or dict(coming from browser or)
            if isinstance(provider.identity.identity_id, dict):
                html_identity = provider.identity.identity_id.get(
                    "userPrincipalName", "Identity not found"
                )
            else:
                html_identity = provider.identity.identity_id
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Azure Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>Azure Tenant IDs:</b> {" ".join(provider.identity.tenant_ids)}
                            </li>
                            <li class="list-group-item">
                                <b>Azure Tenant Domain:</b> {provider.identity.tenant_domain}
                            </li>
                            <li class="list-group-item">
                                <b>Azure Subscriptions:</b> {" ".join(printed_subscriptions)}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        Azure Credentials
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>Azure Identity Type:</b> {provider.identity.identity_type}
                            </li>
                            <li class="list-group-item">
                                <b>Azure Identity ID:</b> {html_identity}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_gcp_assessment_summary(provider: Provider) -> str:
        """
        get_gcp_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            try:
                getattr(provider.session, "_service_account_email")
                profile = (
                    provider.session._service_account_email
                    if provider.session._service_account_email is not None
                    else "default"
                )
            except AttributeError:
                profile = "default"
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            GCP Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>GCP Project IDs:</b> {", ".join(provider.project_ids)}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            GCP Credentials
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>GCP Account:</b> {profile}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_kubernetes_assessment_summary(provider: Provider) -> str:
        """
        get_kubernetes_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            Kubernetes Assessment Summary
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>Kubernetes Cluster:</b> {provider.identity.cluster}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="card">
                        <div class="card-header">
                            Kubernetes Credentials
                        </div>
                        <ul class="list-group
                        list-group-flush">
                            <li class="list-group-item">
                                <b>Kubernetes Context:</b> {provider.identity.context}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_m365_assessment_summary(provider: Provider) -> str:
        """
        get_m365_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            M365 Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>M365 Tenant Domain:</b> {provider.identity.tenant_domain}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        M365 Credentials
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>M365 Identity Type:</b> {provider.identity.identity_type}
                            </li>
                            <li class="list-group-item">
                                <b>M365 Identity ID:</b> {provider.identity.identity_id}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    def get_nhn_assessment_summary(provider: Provider) -> str:
        """
        get_nhn_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            return f"""
                <div class="col-md-2">
                    <div class="card">
                        <div class="card-header">
                            NHN Assessment Summary
                        </div>
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item">
                                <b>NHN Tenant Domain:</b> {provider.identity.tenant_domain}
                            </li>
                        </ul>
                    </div>
                </div>
                <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        NHN Credentials
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>NHN Identity Type:</b> {provider.identity.identity_type}
                            </li>
                            <li class="list-group-item">
                                <b>NHN Identity ID:</b> {provider.identity.identity_id}
                            </li>
                        </ul>
                    </div>
                </div>"""
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""

    @staticmethod
    def get_assessment_summary(provider: Provider) -> str:
        """
        get_assessment_summary gets the HTML assessment summary for the provider

        Args:
            provider (Provider): the provider object

        Returns:
            str: the HTML assessment summary
        """
        try:
            # This is based in the Provider_provider class
            # It is not pretty but useful
            # AWS_provider --> aws
            # GCP_provider --> gcp
            # Azure_provider --> azure
            # Kubernetes_provider --> kubernetes

            # Dynamically get the Provider quick inventory handler
            provider_html_assessment_summary_function = (
                f"get_{provider.type}_assessment_summary"
            )
            return getattr(HTML, provider_html_assessment_summary_function)(provider)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            return ""
