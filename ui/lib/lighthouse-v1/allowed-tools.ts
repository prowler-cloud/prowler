/**
 * Tools explicitly allowed for the LLM to list and execute.
 * Follows the principle of least privilege - only these tools are accessible.
 * All other tools are blocked by default.
 */
const ALLOWED_TOOLS = new Set([
  // === Prowler Hub Tools - read-only ===
  "prowler_hub_list_checks",
  "prowler_hub_semantic_search_checks",
  "prowler_hub_get_check_details",
  "prowler_hub_get_check_code",
  "prowler_hub_get_check_fixer",
  "prowler_hub_list_compliances",
  "prowler_hub_semantic_search_compliances",
  "prowler_hub_get_compliance_details",
  "prowler_hub_list_providers",
  "prowler_hub_get_provider_services",
  // === Prowler Docs Tools - read-only ===
  "prowler_docs_search",
  "prowler_docs_get_document",
  // === Prowler platform Tools - read-only ===
  // Findings
  "prowler_search_security_findings",
  "prowler_get_finding_details",
  "prowler_get_findings_overview",
  // Finding Groups
  "prowler_list_finding_groups",
  "prowler_get_finding_group_details",
  "prowler_list_finding_group_resources",
  // Providers
  "prowler_search_providers",
  // Scans
  "prowler_list_scans",
  "prowler_get_scan",
  // Muting
  "prowler_get_mutelist",
  "prowler_list_mute_rules",
  "prowler_get_mute_rule",
  // Compliance
  "prowler_get_compliance_overview",
  "prowler_get_compliance_framework_state_details",
  // Resources
  "prowler_list_resources",
  "prowler_get_resource",
  "prowler_get_resource_events",
  "prowler_get_resources_overview",
  // Attack Paths
  "prowler_list_attack_paths_queries",
  "prowler_list_attack_paths_scans",
  "prowler_run_attack_paths_query",
  "prowler_get_attack_paths_cartography_schema",
]);

/**
 * Check if a tool is allowed for LLM access.
 * Returns true only if the tool is explicitly in the whitelist.
 *
 * The Prowler platform tools were renamed from the `prowler_app_` prefix to
 * `prowler_`. The legacy prefix is normalized here so tools served by
 * an older MCP server (or a mismatched rollout) still resolve.
 */
export function isAllowedTool(toolName: string): boolean {
  const normalized = toolName.startsWith("prowler_app_")
    ? toolName.replace(/^prowler_app_/, "prowler_")
    : toolName;
  return ALLOWED_TOOLS.has(normalized);
}
