import type {
  AiFrameworkSection,
  AiSecurityOverview,
  AiStackProvider,
} from "@/app/(prowler)/ai-security/_types";

// shortcut: the page runs on this fixture and ignores the scope filters;
// replace it with a server action in `_actions/` when the gen-ai overview
// endpoints exist. `?preview=` picks the state to look at meanwhile.
export const AI_SECURITY_PREVIEW = {
  EMPTY: "empty",
  LOCKED: "locked",
} as const;

const provider = (
  type: string,
  name: string,
  scope: string,
  pass: number,
  fail: number,
  manual: number,
): AiStackProvider => ({
  type,
  name,
  scope,
  connected: true,
  pass,
  fail,
  manual,
});

const section = (
  code: string,
  name: string,
  pass: number,
  fail: number,
  manual: number,
): AiFrameworkSection => ({ code, name, pass, fail, manual });

const MOCK_OVERVIEW: AiSecurityOverview = {
  pass: 360,
  fail: 143,
  manual: 35,
  newFailed: 12,
  fixed: 5,
  severity: { critical: 9, high: 31, medium: 61, low: 42, informational: 0 },
  layers: [
    {
      id: "model-vendors",
      name: "Model vendors",
      description:
        "Organization settings, API keys, GPTs and connectors in the vendor accounts.",
      providers: [
        provider("claude", "Claude", "1 organization", 96, 21, 34),
        provider("openai", "OpenAI", "1 organization", 41, 14, 1),
        provider("chatgpt", "ChatGPT", "1 workspace", 29, 18, 0),
      ],
    },
    {
      id: "cloud-ai",
      name: "Cloud AI",
      description:
        "Agents, knowledge bases, guardrails and invocation logging in your clouds.",
      providers: [
        provider("aws", "Amazon Bedrock", "4 accounts", 112, 37, 0),
        provider("aws", "Bedrock AgentCore", "2 accounts", 18, 6, 0),
      ],
    },
    {
      id: "developer-platforms",
      name: "Developer platforms",
      description:
        "Workflows that run AI agents, and provider keys committed to code.",
      providers: [
        provider("github", "GitHub", "2 organizations", 64, 47, 0),
        {
          ...provider("supabase", "Supabase", "", 0, 0, 0),
          connected: false,
        },
      ],
    },
  ],
  frameworks: [
    {
      id: "owasp_llm_top_10_2025",
      shortName: "OWASP LLM Top 10",
      name: "OWASP Top 10 for LLM Applications",
      version: "2025",
      unit: "requirements",
      sections: [
        section("LLM01", "Prompt injection", 3, 1, 3),
        section("LLM02", "Sensitive information disclosure", 3, 2, 7),
        section("LLM03", "Supply chain", 2, 1, 7),
        section("LLM04", "Data and model poisoning", 4, 0, 6),
        section("LLM05", "Improper output handling", 1, 0, 6),
        section("LLM06", "Excessive agency", 3, 3, 4),
        section("LLM07", "System prompt leakage", 2, 0, 2),
        section("LLM08", "Vector and embedding weaknesses", 1, 1, 2),
        section("LLM09", "Misinformation", 1, 0, 7),
        section("LLM10", "Unbounded consumption", 5, 1, 9),
      ],
    },
    {
      id: "nist_ai_rmf_1.0",
      shortName: "NIST AI RMF",
      name: "NIST AI Risk Management Framework",
      version: "1.0",
      unit: "subcategories",
      sections: [
        section("GV", "Govern", 4, 2, 13),
        section("MP", "Map", 2, 1, 15),
        section("MS", "Measure", 5, 3, 14),
        section("MG", "Manage", 3, 2, 8),
      ],
    },
    {
      id: "iso42001_2023",
      shortName: "ISO/IEC 42001",
      name: "ISO/IEC 42001 Annex A controls",
      version: "2023",
      unit: "controls",
      sections: [
        section("A.2", "Policies related to AI", 0, 0, 3),
        section("A.3", "Internal organization", 1, 0, 1),
        section("A.4", "Resources for AI systems", 2, 1, 2),
        section("A.5", "Assessing impacts of AI systems", 0, 0, 4),
        section("A.6", "AI system life cycle", 3, 2, 4),
        section("A.7", "Data for AI systems", 2, 1, 2),
        section("A.8", "Information for interested parties", 1, 0, 3),
        section("A.9", "Use of AI systems", 1, 1, 1),
        section("A.10", "Third-party and customer relationships", 1, 1, 1),
      ],
    },
    {
      id: "owasp_agentic_top_10_2026",
      shortName: "OWASP Agentic Top 10",
      name: "OWASP Top 10 for Agentic Applications",
      version: "2026",
      unit: "requirements",
      sections: [
        section("ASI01", "Agent goal hijack", 1, 1, 2),
        section("ASI02", "Tool misuse and exploitation", 2, 2, 1),
        section("ASI03", "Identity and privilege abuse", 3, 1, 1),
        section("ASI04", "Agentic supply chain vulnerabilities", 2, 1, 1),
        section("ASI05", "Unexpected code execution", 2, 1, 1),
        section("ASI06", "Memory and context poisoning", 1, 0, 2),
        section("ASI07", "Insecure inter-agent communication", 0, 0, 3),
        section("ASI08", "Cascading failures", 0, 0, 3),
        section("ASI09", "Human-agent trust exploitation", 0, 0, 3),
        section("ASI10", "Rogue agents", 1, 1, 2),
      ],
    },
    {
      id: "eu_ai_act_2024",
      shortName: "EU AI Act",
      name: "EU AI Act, deployer obligations",
      version: "Regulation (EU) 2024/1689",
      unit: "requirements",
      note: "Informative mapping. Prowler checks the parts of these articles that show up in configuration, mostly the deployer duties in Article 26. Whether a system is high-risk is your call and stays manual.",
      sections: [
        section("Art. 4", "AI literacy", 0, 0, 1),
        section("Art. 9", "Risk management system", 0, 0, 3),
        section("Art. 10", "Data and data governance", 1, 0, 2),
        section("Art. 12", "Record-keeping", 1, 1, 0),
        section("Art. 14", "Human oversight", 1, 1, 0),
        section("Art. 15", "Accuracy, robustness and cybersecurity", 2, 1, 0),
        section("Art. 26", "Obligations of deployers", 3, 2, 1),
        section("Art. 50", "Transparency obligations", 0, 0, 2),
      ],
    },
    {
      id: "claude_workspace_baseline_1.0_claude",
      shortName: "Claude Workspace Baseline",
      name: "Claude Workspace Security and Data Privacy Baseline",
      version: "1.0, Claude only",
      unit: "requirements",
      sections: [
        section("", "Data privacy and retention", 7, 1, 7),
        section("", "Claude Code governance", 3, 2, 4),
        section("", "Access and authentication", 6, 2, 0),
        section("", "Identity lifecycle", 5, 1, 2),
        section("", "Programmatic credentials", 5, 3, 0),
        section("", "Connectors and extensions", 1, 1, 6),
        section("", "Audit and monitoring", 5, 1, 1),
        section("", "Content sharing", 0, 0, 6),
        section("", "Code execution and Cowork", 0, 0, 6),
        section("", "Workspace segmentation", 1, 0, 2),
      ],
    },
  ],
  topRisks: [
    {
      checkId: "githubactions_ai_agent_untrusted_trigger",
      title: "AI agent runs on an untrusted pull request trigger",
      severity: "critical",
      providerName: "GitHub",
      affected: "3 workflows",
    },
    {
      checkId: "repository_ai_provider_key_not_committed",
      title: "Anthropic or OpenAI key committed to a repository",
      severity: "critical",
      providerName: "GitHub",
      affected: "2 repositories",
    },
    {
      checkId: "claudecode_bypass_permissions_disabled",
      title: "Claude Code can skip permission prompts",
      severity: "critical",
      providerName: "Claude",
      affected: "1 organization",
    },
    {
      checkId: "gpt_custom_actions_disabled",
      title: "Custom GPTs call external actions",
      severity: "high",
      providerName: "ChatGPT",
      affected: "7 GPTs",
    },
    {
      checkId: "bedrock_agent_role_least_privilege",
      title: "Agent role can do more than the agent needs",
      severity: "high",
      providerName: "AWS",
      affected: "4 agents",
    },
    {
      checkId: "project_not_externally_shared",
      title: "Projects shared outside the workspace",
      severity: "high",
      providerName: "ChatGPT",
      affected: "4 projects",
    },
  ],
  inventory: [
    [
      "bedrock-agent",
      "Agents and flows",
      23,
      "Bedrock, AgentCore",
      "6 without a guardrail",
    ],
    [
      "bedrock-knowledge-base",
      "Knowledge bases",
      7,
      "Bedrock",
      "2 not encrypted with your key",
    ],
    [
      "bedrock-guardrail",
      "Guardrails",
      12,
      "Bedrock",
      "3 without a prompt attack filter",
    ],
    ["chatgpt-gpt", "Custom GPTs", 41, "ChatGPT", "7 call external actions"],
    [
      "project",
      "Workspaces and projects",
      38,
      "Claude, OpenAI, ChatGPT",
      "4 shared outside the workspace",
    ],
    [
      "api-key",
      "API keys",
      96,
      "Claude, OpenAI, Bedrock",
      "11 not rotated in 6 months",
    ],
    [
      "claude-connector",
      "Connectors",
      14,
      "Claude",
      "2 with tools always allowed",
    ],
    [
      "github-workflow",
      "AI workflows in CI",
      18,
      "GitHub",
      "3 on untrusted triggers",
    ],
  ].map(([resourceType, label, count, providers, issue]) => ({
    resourceType: String(resourceType),
    label: String(label),
    count: Number(count),
    providers: String(providers),
    issue: String(issue),
  })),
};

const EMPTY_OVERVIEW: AiSecurityOverview = {
  pass: 0,
  fail: 0,
  manual: 0,
  newFailed: 0,
  fixed: 0,
  severity: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
  layers: [],
  frameworks: [],
  topRisks: [],
  inventory: [],
};

/** Null means the overview could not be loaded. */
export const getAiSecurityOverview = async (
  preview?: string,
): Promise<AiSecurityOverview | null> =>
  preview === AI_SECURITY_PREVIEW.EMPTY ? EMPTY_OVERVIEW : MOCK_OVERVIEW;
