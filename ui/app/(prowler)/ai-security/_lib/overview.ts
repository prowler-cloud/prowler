import type {
  FindingsSeverityAttributes,
  FindingsStatusAttributes,
} from "@/actions/overview";
import type {
  AiFramework,
  AiFrameworkSection,
  AiRequirement,
  AiSecurityOverview,
  AiTopRisk,
} from "@/app/(prowler)/ai-security/_types";
import type { CrossProviderRequirementData } from "@/app/(prowler)/compliance/_types";
import { splitCsvFilterValues } from "@/lib/findings-filters";
import type { SearchParamsProps } from "@/types";
import {
  type AttributesItemData,
  type ComplianceOverviewData,
  REQUIREMENT_STATUS,
  type RequirementItemData,
  type RequirementStatus,
} from "@/types/compliance";
import type { ProviderProps, ProviderType } from "@/types/providers";
import { SEVERITY_LEVELS, type SeverityLevel } from "@/types/severities";

export const AI_SECURITY_PREVIEW = {
  EMPTY: "empty",
  LOCKED: "locked",
} as const;

/** The model vendors installed from the Registry. Every check they run is an AI check. */
const AI_PROVIDERS = {
  claude: "Claude",
  openai: "OpenAI",
  chatgpt: "ChatGPT",
} as const;

type AiProviderType = keyof typeof AI_PROVIDERS;

const AI_PROVIDER_TYPES = Object.keys(AI_PROVIDERS) as AiProviderType[];

type AiFrameworkInfo = Pick<AiFramework, "shortName" | "name" | "unit"> &
  Partial<Pick<AiFramework, "note">>;

/** The AI frameworks the page shows when the tenant has them installed, keyed by compliance id. */
export const AI_FRAMEWORKS: Record<string, AiFrameworkInfo> = {
  owasp_llm_top_10_2025: {
    shortName: "OWASP LLM Top 10",
    name: "OWASP Top 10 for LLM Applications",
    unit: "requirements",
  },
  owasp_agentic_top_10_2026: {
    shortName: "OWASP Agentic Top 10",
    name: "OWASP Top 10 for Agentic Applications",
    unit: "requirements",
  },
  owasp_mcp_top_10_2025: {
    shortName: "OWASP MCP Top 10",
    name: "OWASP MCP Top 10",
    unit: "requirements",
  },
  "nist_ai_rmf_1.0": {
    shortName: "NIST AI RMF",
    name: "NIST AI Risk Management Framework",
    unit: "subcategories",
  },
  iso_42001_2023: {
    shortName: "ISO/IEC 42001",
    name: "ISO/IEC 42001 Annex A controls",
    unit: "controls",
  },
  eu_ai_act_2024: {
    shortName: "EU AI Act",
    name: "EU AI Act, deployer obligations",
    unit: "requirements",
    note: "Informative mapping. Prowler checks the parts of these articles that show up in configuration, mostly the deployer duties in Article 26. Whether a system is high-risk is your call and stays manual.",
  },
};

const SCOPE_KEYS = [
  "filter[provider_id__in]",
  "filter[provider_groups__in]",
] as const;

/**
 * The page's provider filters narrowed to the AI providers, or null when the
 * selected provider types leave none of them.
 */
export function aiScopeFilters(
  searchParams: SearchParamsProps,
): Record<string, string> | null {
  const selected = splitCsvFilterValues(
    searchParams["filter[provider_type__in]"],
  );
  const types = AI_PROVIDER_TYPES.filter(
    (type) => selected.length === 0 || selected.includes(type),
  );
  if (types.length === 0) return null;

  const filters: Record<string, string> = {
    "filter[provider_type__in]": types.join(","),
  };
  for (const key of SCOPE_KEYS) {
    const value = splitCsvFilterValues(searchParams[key]).join(",");
    if (value) filters[key] = value;
  }
  return filters;
}

/**
 * The AI providers of every type the account filter allows. The AI stack
 * lists them all, so a row can switch the page to another provider type.
 */
export function aiProvidersInScope(
  providers: ProviderProps[],
  filters: Record<string, string>,
) {
  const ids = filters["filter[provider_id__in]"]?.split(",");
  return providers.filter(
    (provider) =>
      Object.hasOwn(AI_PROVIDERS, provider.attributes.provider) &&
      (!ids || ids.includes(provider.id)),
  );
}

export interface AiFindingGroup {
  id: string;
  attributes: {
    check_title: string | null;
    status: RequirementStatus;
    severity: string;
    impacted_providers: string[];
    resources_fail: number;
  };
}

export interface AiFrameworkSource {
  overview: ComplianceOverviewData;
  requirements: RequirementItemData[];
  attributes: AttributesItemData[];
}

export interface AiOverviewSources {
  /** The AI providers the stack lists. */
  providers: ProviderProps[];
  /** The provider types the page is filtered to; the totals count only these. */
  types: string[];
  /** The latest scans' results of each AI provider type the stack lists. */
  results: Partial<Record<string, FindingsStatusAttributes>>;
  /** Failed findings by severity. */
  severity: FindingsSeverityAttributes;
  frameworks: AiFrameworkSource[];
  /** Failed checks, most severe first. */
  findingGroups: AiFindingGroup[];
}

const plural = (count: number, word: string) =>
  `${count.toLocaleString()} ${word}${count === 1 ? "" : "s"}`;

const isSeverityLevel = (value: string): value is SeverityLevel =>
  (SEVERITY_LEVELS as readonly string[]).includes(value);

const providerName = (type: string) =>
  AI_PROVIDERS[type as AiProviderType] ?? type;

/** "LLM01:2025 Prompt Injection" → code "LLM01"; a label without a numbered code keeps it all as the name. */
export function parseSection(
  label: string,
): Pick<AiFrameworkSection, "code" | "name"> {
  const [first, ...rest] = label.split(" ");
  if (rest.length === 0 || !/\d/.test(first)) return { code: "", name: label };
  return { code: first.split(":")[0], name: rest.join(" ") };
}

function toFramework({
  overview,
  requirements,
  attributes,
}: AiFrameworkSource): AiFramework {
  const sectionOf = new Map(
    attributes.map((item) => {
      const [metadata] = item.attributes.attributes.metadata as {
        Section?: string;
      }[];
      return [item.id, metadata?.Section ?? ""];
    }),
  );
  // Sections keep the framework's order; requirements without one go last.
  const sections = new Map<string, AiFrameworkSection>(
    Array.from(new Set([...Array.from(sectionOf.values()), ""])).map(
      (label) => [
        label,
        {
          id: label,
          ...parseSection(label || "Other"),
          pass: 0,
          fail: 0,
          manual: 0,
        },
      ],
    ),
  );
  for (const requirement of requirements) {
    const section = sections.get(sectionOf.get(requirement.id) ?? "");
    const status = requirement.attributes.status;
    if (!section) continue;
    if (status === "PASS") section.pass += 1;
    else if (status === "FAIL") section.fail += 1;
    else section.manual += 1;
  }

  return {
    id: overview.id,
    version: overview.attributes.version,
    ...AI_FRAMEWORKS[overview.id],
    sections: Array.from(sections.values()).filter(
      (section) => section.pass + section.fail + section.manual > 0,
    ),
  };
}

const toTopRisk = ({ id, attributes }: AiFindingGroup): AiTopRisk | null =>
  isSeverityLevel(attributes.severity)
    ? {
        checkId: id,
        title: attributes.check_title ?? id,
        severity: attributes.severity,
        providerName: attributes.impacted_providers
          .map(providerName)
          .join(", "),
        affected: plural(attributes.resources_fail, "resource"),
      }
    : null;

/** Maps the overview, compliance and finding-group responses to what the widgets show. */
export function toAiSecurityOverview({
  providers,
  types,
  results,
  severity,
  frameworks,
  findingGroups,
}: AiOverviewSources): AiSecurityOverview {
  const vendors = AI_PROVIDER_TYPES.map((type) => {
    const accounts = providers.filter(
      (provider) => provider.attributes.provider === type,
    ).length;
    const result = results[type];
    const pass = result?.pass ?? 0;
    const fail = result?.fail ?? 0;
    // Overview totals count every status; what is neither pass, fail nor muted is manual.
    const manual = result
      ? Math.max(result.total - pass - fail - result.muted, 0)
      : 0;
    return {
      type,
      name: AI_PROVIDERS[type],
      scope: plural(accounts, "account"),
      connected: accounts > 0,
      pass,
      fail,
      manual,
    };
  });

  const inScope = vendors.filter((vendor) => types.includes(vendor.type));

  return {
    pass: inScope.reduce((sum, vendor) => sum + vendor.pass, 0),
    fail: inScope.reduce((sum, vendor) => sum + vendor.fail, 0),
    manual: inScope.reduce((sum, vendor) => sum + vendor.manual, 0),
    severity: { ...severity },
    layers: [
      {
        id: "model-vendors",
        name: "Model vendors",
        description:
          "Organization settings, API keys, projects and connectors in the vendor accounts.",
        providers: vendors,
      },
    ],
    frameworks: frameworks
      .filter(({ overview }) => Object.hasOwn(AI_FRAMEWORKS, overview.id))
      .map(toFramework),
    topRisks: findingGroups
      .map(toTopRisk)
      .filter((risk): risk is AiTopRisk => risk !== null),
  };
}

const requirementSection = ({ attributes }: CrossProviderRequirementData) =>
  typeof attributes.Section === "string" ? attributes.Section : "";

const requirementChecks = (
  requirement: CrossProviderRequirementData,
  types: string[],
) =>
  Array.from(
    new Set(
      types.flatMap(
        (type) =>
          requirement.check_ids_by_provider?.[type as ProviderType] ?? [],
      ),
    ),
  );

/** The checks the provider types run for a framework section's requirements. */
export const aiSectionChecks = (
  requirements: CrossProviderRequirementData[],
  section: string,
  types: string[],
) =>
  Array.from(
    new Set(
      requirements
        .filter((requirement) => requirementSection(requirement) === section)
        .flatMap((requirement) => requirementChecks(requirement, types)),
    ),
  );

/** A framework section's requirements with each check's result in the latest scans. */
export function toAiRequirements({
  requirements,
  section,
  types,
  findingGroups,
}: {
  requirements: CrossProviderRequirementData[];
  section: string;
  /** The provider types in scope; a requirement without their checks is manual. */
  types: string[];
  /** The finding groups of the section's checks. */
  findingGroups: AiFindingGroup[];
}): AiRequirement[] {
  const groups = new Map(
    findingGroups.map((group) => [group.id, group.attributes]),
  );
  return requirements
    .filter((requirement) => requirementSection(requirement) === section)
    .map((requirement) => {
      const checks = requirementChecks(requirement, types).map((id) => {
        const group = groups.get(id);
        return {
          id,
          title: group?.check_title ?? id,
          status: group?.status ?? REQUIREMENT_STATUS.NO_FINDINGS,
          failedResources: group?.resources_fail ?? 0,
        };
      });
      return {
        id: requirement.id,
        name: requirement.name,
        description: requirement.description,
        status:
          checks.length > 0 ? requirement.status : REQUIREMENT_STATUS.MANUAL,
        checks,
      };
    });
}
