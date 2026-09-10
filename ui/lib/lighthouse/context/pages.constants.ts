import {
  LIGHTHOUSE_PAGE_ID,
  type LighthousePageDefinitionInput,
  type LighthousePageSuggestions,
} from "@/types/lighthouse-context";

const PROVIDER_SCOPE_PARAMS = [
  "filter[provider__in]",
  "filter[provider_id__in]",
  "filter[provider_uid]",
  "filter[provider_uid__in]",
  "filter[provider_type__in]",
  "filter[provider]",
  "filter[provider_type]",
  "filter[provider_groups__in]",
] as const;

const COMMON_LIST_PARAMS = [
  "query",
  "search",
  "filter[search]",
  "sort",
] as const;

export const LIGHTHOUSE_GLOBAL_SUGGESTIONS = [
  {
    label: "Identify biggest security risk",
    prompt:
      "Pull my findings, compliance gaps, and attack paths together into one picture. What's my single biggest security risk right now, and how confident are you?",
  },
  {
    label: "Review stale mute rules",
    prompt:
      "Which of my mute rules are hiding something that now matters — rules written for a resource that changed, or an exception nobody has revisited?",
  },
  {
    label: "Find missing alerts",
    prompt:
      "Look at my most serious findings from the last month. Which of them produced no alert from Prowler, and what rule would have caught them?",
  },
  {
    label: "Create Jira tickets",
    prompt:
      "Turn my top security work into Jira tickets: group related findings into one ticket per root cause, write each so an engineer can act on it without coming back to ask me questions, and tell me which project each should go to.",
  },
] as const satisfies LighthousePageSuggestions;

export const LIGHTHOUSE_PAGE_DEFINITION_INPUTS = [
  {
    id: LIGHTHOUSE_PAGE_ID.OVERVIEW,
    label: "Overview",
    match: (pathname) => pathname === "/",
    allowedSearchParams: PROVIDER_SCOPE_PARAMS,
    suggestions: [
      {
        label: "Prioritize cross-surface risk",
        prompt:
          "Across my providers, services, and frameworks, which risk should I prioritize first, and why?",
      },
      {
        label: "Improve my ThreatScore",
        prompt:
          "According to the Prowler ThreatScore, what do I need to improve first based on its trend and weakest section, and why?",
      },
      {
        label: "Plan today's security work",
        prompt: "Build a practical security plan for today.",
      },
      {
        label: "Find coverage blind spots",
        prompt:
          "What's missing from this dashboard that should worry me — providers not onboarded, regions or services with no scan coverage, checks that never run?",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.FINDINGS,
    label: "Findings",
    match: (pathname) => pathname === "/findings",
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      ...COMMON_LIST_PARAMS,
      "filter[region__in]",
      "filter[service__in]",
      "filter[severity__in]",
      "filter[status__in]",
      "filter[delta]",
      "filter[delta__in]",
      "filter[resource_type__in]",
      "filter[category__in]",
      "filter[resource_groups__in]",
      "filter[scan]",
      "filter[scan__in]",
      "filter[scan_id]",
      "filter[scan_id__in]",
      "filter[inserted_at]",
      "filter[muted]",
    ],
    suggestions: [
      {
        label: "Generate concrete remediation",
        prompt:
          "Give me the actual remediation for the top failing check here: the commands and IaC changes (if possible, with Terraform preferred), the blast radius of applying them, and what to verify afterward.",
      },
      {
        label: "Re-rank by real exposure",
        prompt:
          "Severity here is the check's label, not my actual risk. Re-rank these by real exposure, whether the affected resource is internet-facing, production, or holds data; and give me the true top five.",
      },
      {
        label: "Group by shared fix",
        prompt:
          "Group these by the underlying change that fixes them, the same IAM policy, module, or baseline; not by check. Which single change clears the most findings?",
      },
      {
        label: "Build remediation plan",
        prompt: "Create a remediation plan for this findings view.",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.RESOURCES,
    label: "Resources",
    match: (pathname) => pathname === "/resources",
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      ...COMMON_LIST_PARAMS,
      "filter[region__in]",
      "filter[service__in]",
      "filter[type__in]",
      "filter[groups__in]",
    ],
    suggestions: [
      {
        label: "Choose attacker's first target",
        prompt:
          "What's the first thing among these resources you'd target in an attack, what would it give you, and how far could you pivot from there?",
      },
      {
        label: "Find architectural security debt",
        prompt:
          "What does this inventory tell you about how this environment was built, and where does that design create security debt?",
      },
      {
        label: "Create team action lists",
        prompt:
          "Turn this inventory into a per-team action list. Infer likely owners from tags and naming, and give each team their top three fixes.",
      },
      {
        label: "Build hardening plan",
        prompt: "Recommend a hardening plan for this resource scope.",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.COMPLIANCE_DETAIL,
    label: "Compliance detail",
    match: (pathname) => pathname.startsWith("/compliance/"),
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      "scanId",
      "scan_id",
      "complianceId",
      "section",
      "mode",
      "version",
      "filter[cis_profile_level]",
      "filter[region__in]",
      "filter[status__in]",
    ],
    suggestions: [
      {
        label: "Prioritize failed requirements",
        prompt: "Which failed requirements need attention first?",
      },
      {
        label: "Identify manual evidence",
        prompt:
          "Which requirements here can't be satisfied by scanning at all? Tell me exactly what evidence to collect, who owns it, and what good evidence looks like.",
      },
      {
        label: "Rehearse weakest-section audit",
        prompt:
          "Play the auditor for my weakest section. What will you ask me, what evidence will you want to see, and where am I going to struggle?",
      },
      {
        label: "Improve framework score",
        prompt: "Create a plan to improve this framework score.",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.COMPLIANCE,
    label: "Compliance",
    match: (pathname) => pathname === "/compliance",
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      "tab",
      "scanId",
      "scan_id",
      "framework",
      "version",
      "mode",
      "section",
      "filter[compliance_id]",
      "filter[region__in]",
    ],
    suggestions: [
      {
        label: "Summarize compliance gaps",
        prompt: "Summarize the most important compliance gaps.",
      },
      {
        label: "Prioritize frameworks",
        prompt: "Which frameworks should I prioritize?",
      },
      {
        label: "Explain compliance score",
        prompt: "Explain the visible compliance score.",
      },
      {
        label: "Estimate path to passing",
        prompt:
          "How much work is it to take my weakest framework to passing? Break it down by provider account into a few sprints, with what lands first.",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.ATTACK_PATHS,
    label: "Attack Paths",
    match: (pathname) => pathname.startsWith("/attack-paths"),
    allowedSearchParams: ["scanId", "queryId"],
    suggestions: [
      {
        label: "Explain current attack path",
        prompt: "Explain the current attack path.",
      },
      {
        label: "Find critical graph nodes",
        prompt: "Which nodes are most critical in this graph?",
      },
      {
        label: "Choose first break point",
        prompt: "Where should I break this attack path first?",
      },
      {
        label: "Recommend attack path fixes",
        prompt: "Recommend remediations for the current attack path.",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.SCANS,
    label: "Scans",
    match: (pathname) => pathname.startsWith("/scans"),
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      ...COMMON_LIST_PARAMS,
      "tab",
      "scanId",
      "filter[state]",
      "filter[state__in]",
      "filter[trigger]",
    ],
    suggestions: [
      {
        label: "Summarize scan activity",
        prompt: "Summarize recent scan activity.",
      },
      {
        label: "Check release regressions",
        prompt:
          "I'm shipping to production. Scan now and tell me if anything regressed versus the last run.",
      },
      {
        label: "Rescan stale providers",
        prompt:
          "Which providers have never been scanned or haven't been scanned recently? Rescan the ones that matter.",
      },
      {
        label: "Set recurring scans",
        prompt:
          "Which of my providers don't have a recurring scan? Tell me which ones should, and set up scheduled scans with the right frequency.",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.PROVIDERS,
    label: "Providers",
    match: (pathname) => pathname === "/providers",
    allowedSearchParams: [
      ...PROVIDER_SCOPE_PARAMS,
      ...COMMON_LIST_PARAMS,
      "tab",
      "filter[status]",
      "filter[connected]",
    ],
    suggestions: [
      {
        label: "Prioritize providers",
        prompt: "Which visible providers need attention?",
      },
      {
        label: "Find unmonitored cloud accounts",
        prompt:
          "What parts of my cloud estate aren't onboarded? Provider accounts that exist but Prowler isn't scanning.",
      },
      {
        label: "Design provider groups",
        prompt:
          "Group these provider accounts by what they're actually for, based on names, tags, and what's running in them. Which of those groupings should exist as provider groups in Prowler but don't?",
      },
      {
        label: "Complete provider setup",
        prompt:
          "Which accounts were added recently but never fully configured — no schedule, no groups, no successful scan?",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.ALERTS,
    label: "Alerts",
    match: (pathname) => pathname === "/alerts",
    allowedSearchParams: [
      "filter[search]",
      "sort",
      "filter[enabled]",
      "filter[trigger]",
    ],
    suggestions: [
      {
        label: "Tune alert rules",
        prompt: "Which alert rules should I enable or tune?",
      },
      {
        label: "Find alerting gaps",
        prompt: "Summarize my alerting coverage and its gaps.",
      },
      {
        label: "Review noisy rules",
        prompt: "Could any alert rule be too noisy or too broad?",
      },
      {
        label: "Design critical alerts",
        prompt: "Design an alerting strategy for critical findings.",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.SERVICES,
    label: "Services",
    match: (pathname) => pathname === "/services",
    allowedSearchParams: [...PROVIDER_SCOPE_PARAMS, ...COMMON_LIST_PARAMS],
    suggestions: [
      {
        label: "Prioritize risky services",
        prompt: "Which services carry the most failing findings?",
      },
      {
        label: "Compare service risk",
        prompt: "Compare risk across my cloud services.",
      },
      {
        label: "Choose services to harden",
        prompt: "Which services should I harden first?",
      },
      {
        label: "Review service coverage",
        prompt: "Summarize service coverage across providers.",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.WORKLOADS,
    label: "Workloads",
    match: (pathname) => pathname === "/workloads",
    allowedSearchParams: [...PROVIDER_SCOPE_PARAMS],
    suggestions: [
      {
        label: "Find exposed workloads",
        prompt: "Which workloads look most exposed?",
      },
      {
        label: "Group workloads for triage",
        prompt: "How should I group workloads for triage?",
      },
      {
        label: "Prioritize workloads",
        prompt: "Which workloads need attention first?",
      },
      {
        label: "Build workload hardening plan",
        prompt: "Build a workload hardening plan.",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.MUTELIST,
    label: "Mute list",
    match: (pathname) => pathname === "/mutelist",
    allowedSearchParams: [...COMMON_LIST_PARAMS, "tab"],
    suggestions: [
      {
        label: "Explain active mute rules",
        prompt: "Which mute rules are active and why?",
      },
      {
        label: "Find hidden findings",
        prompt: "Could a mute rule be hiding important findings?",
      },
      {
        label: "Review risky exclusions",
        prompt: "Review my mute rules for risky exclusions.",
      },
      {
        label: "Structure mute rules safely",
        prompt: "How should I structure mute rules safely?",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.ROLES,
    label: "Roles",
    match: (pathname) =>
      pathname === "/roles" || pathname.startsWith("/roles/"),
    allowedSearchParams: [...COMMON_LIST_PARAMS, "filter[permission_state]"],
    suggestions: [
      {
        label: "Review role permissions",
        prompt:
          "Review the roles on this page. Which ones grant more than their name implies, and what would you trim first?",
      },
      {
        label: "Find overlapping roles",
        prompt:
          "Which of these roles overlap enough to be merged, and does any combination of them add up to an escalation risk?",
      },
      {
        label: "Design least privilege",
        prompt:
          "Propose a least-privilege role set for my team: which roles should exist, what should each allow, and how do I migrate from the current ones?",
      },
      {
        label: "Audit unlimited visibility",
        prompt:
          "Which roles have unlimited visibility across providers, and who actually needs to keep it?",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.USERS,
    label: "Users",
    match: (pathname) =>
      pathname === "/users" || pathname.startsWith("/users/"),
    allowedSearchParams: [...COMMON_LIST_PARAMS],
    suggestions: [
      {
        label: "Audit user access",
        prompt:
          "Review the users listed here. Who holds admin-level roles, and does anyone look over-privileged for what they do?",
      },
      {
        label: "Find concentrated ownership",
        prompt:
          "Is any critical responsibility — provider management, user administration, billing — concentrated in a single person here?",
      },
      {
        label: "Plan an access review",
        prompt:
          "Turn this user list into a quarterly access review: who reviews whom, and what should each reviewer verify?",
      },
      {
        label: "Prepare safe offboarding",
        prompt:
          "Draft an offboarding checklist for this tenant: what should be revoked or transferred when one of these users leaves?",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.INVITATIONS,
    label: "Invitations",
    match: (pathname) =>
      pathname === "/invitations" || pathname.startsWith("/invitations/"),
    allowedSearchParams: [...COMMON_LIST_PARAMS, "filter[state]"],
    suggestions: [
      {
        label: "Review pending invitations",
        prompt:
          "Which pending invitations here should be revoked — expired, unfamiliar domains, or broader roles than the invitee needs?",
      },
      {
        label: "Tighten invitation roles",
        prompt:
          "Do any open invitations grant admin or unlimited-visibility roles? Suggest a safer default role for new members.",
      },
      {
        label: "Draft onboarding steps",
        prompt:
          "Draft the checklist a new member should follow after accepting one of these invitations.",
      },
      {
        label: "Explain invitation lifecycle",
        prompt:
          "Explain how invitations work in Prowler: what happens when one expires, and how do I resend or revoke one safely?",
      },
    ],
  },
  {
    id: LIGHTHOUSE_PAGE_ID.INTEGRATIONS,
    label: "Integrations",
    match: (pathname) =>
      pathname === "/integrations" || pathname.startsWith("/integrations/"),
    // The grid page takes no params and sub-pages pin their integration type
    // server-side, so the open integration travels in `path`; only the
    // sub-page tables' sort ever reaches the URL.
    allowedSearchParams: ["sort"],
    suggestions: [
      {
        label: "Review integration coverage",
        prompt:
          "Which integrations am I missing that would get findings to the right team faster — ticketing, chat, or storage?",
      },
      {
        label: "Check integration health",
        prompt:
          "Review the integrations configured here. Are any disconnected, misconfigured, or pointing at destinations nobody watches?",
      },
      {
        label: "Route findings to teams",
        prompt:
          "Design how findings should flow from Prowler into my existing tools so each team only sees what they own.",
      },
      {
        label: "Harden integration credentials",
        prompt:
          "What credentials do these integrations rely on, and how should I scope and rotate them safely?",
      },
    ],
  },
] as const satisfies readonly LighthousePageDefinitionInput[];
