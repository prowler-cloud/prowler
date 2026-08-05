import { ClipboardCheck, ShieldAlert, Waypoints, Wrench } from "lucide-react";

import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

// Skill catalog is UI-defined by design: prompts iterate with a UI deploy, no
// API involved. All findings currently get every skill (no applicability rules).
export const LIGHTHOUSE_SKILLS: LighthouseSkillDefinition[] = [
  {
    id: "investigate-blast-radius",
    name: "Investigate blast radius",
    description:
      "Map identities and resources reachable from the affected resource",
    icon: Waypoints,
    steps: [
      "Gather finding & resource context",
      "Enumerate identities with access",
      "Map reachable resources & services",
      "Assess lateral movement paths",
      "Summarize blast radius",
    ],
    guidance:
      "Quantify the blast radius: counts of identities and resources, the most privileged reachable identity, and the shortest path to sensitive data. Prefer graph/attack-path tools when available.",
    nextSkillId: "verify-exploitability",
    version: 1,
  },
  {
    id: "verify-exploitability",
    name: "Verify exploitability",
    description: "Check real-world exposure and attack preconditions",
    icon: ShieldAlert,
    steps: [
      "Gather finding & resource context",
      "Enumerate attached identities",
      "Check public exposure & trust policy",
      "Query attack paths for lateral movement",
      "Compose exploitability verdict",
    ],
    guidance:
      "Conclude with an explicit verdict (exploitable / not exploitable / needs manual validation), the evidence for it, and the preconditions an attacker needs.",
    nextSkillId: "generate-remediation",
    version: 1,
  },
  {
    id: "generate-remediation",
    name: "Generate remediation",
    description: "Produce a least-privilege configuration and IaC fix",
    icon: Wrench,
    steps: [
      "Gather finding & resource context",
      "Review current configuration",
      "Draft least-privilege fix",
      "Produce IaC remediation",
      "Summarize rollout & risks",
    ],
    guidance:
      "Provide the concrete replacement configuration (policy JSON, settings) plus an infrastructure-as-code patch matching the provider (Terraform preferred), and call out anything that could break when applying it.",
    nextSkillId: "triage-draft-ticket",
    version: 1,
  },
  {
    id: "triage-draft-ticket",
    name: "Triage & draft ticket",
    description: "Assess impact and draft a Jira ticket",
    icon: ClipboardCheck,
    steps: [
      "Gather finding & resource context",
      "Assess impact & urgency",
      "Identify owners & affected systems",
      "Draft the ticket",
    ],
    guidance:
      "End with a ready-to-file ticket: title, severity, description, affected resources, remediation summary, and acceptance criteria — formatted so it can be pasted into Jira as-is.",
    nextSkillId: null,
    version: 1,
  },
];
