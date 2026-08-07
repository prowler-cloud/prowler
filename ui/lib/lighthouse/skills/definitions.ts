import { ClipboardCheck, Scale, Waypoints, Wrench } from "lucide-react";

import {
  LIGHTHOUSE_SKILL_ID,
  type LighthouseSkillDefinition,
} from "@/types/lighthouse-skills";

// Prompts are authored by the DyR team ("Next AI Outcomes" doc) and embedded
// verbatim — do not paraphrase them here. The catalog stays UI-defined by
// design: prompt iterations ship with a UI deploy, no API involved.
const CONTEXTUAL_FIX_PROMPT = `The finding under discussion is the one in the UI context block. If no finding is
present there, ask me for the finding ID before doing anything else.

Give me the remediation for this specific finding, not the generic guidance for the
check.

Start by calling load_tools with these names, in one call:
prowler_get_finding_details, prowler_hub_get_check_details,
prowler_hub_get_check_fixer, prowler_get_resource
You do not need search_tools — I am naming the tools directly.

Then work in this order:

1. prowler_get_finding_details — establish what failed and which resource it is on.
   This also gives you the resource reference you need for step 3.
2. prowler_hub_get_check_details — the rule that produced the finding.
3. prowler_hub_get_check_fixer — if the check has a fixer, get the code. That Python is
   the most reliable description of what the fix actually does, so ground your steps in
   it rather than paraphrasing the check description. If there is no fixer, don't say anything
   about that just continue with your knowledge.
4. prowler_get_resource — the affected resource's real configuration. Base your guidance
   on what is actually set on this resource, not on what the check assumes.

Then write the remediation:

- Open with one sentence on what is wrong with this resource specifically.
- Give the runtime fix using the real identifiers from step 4 — ARN or resource UID,
  account, region, resource name. No placeholders unless a value genuinely cannot be
  determined, in which case say so explicitly.
- Prefer the Prowler Cloud or cloud console path where one exists; give CLI commands
  when they are the practical route.
- State what else the change touches and what I should verify after applying it.
- Close with a short example of what may be producing this in the deployment code
  (Terraform or equivalent). One block, illustrative, not a migration plan.

Keep the whole answer short. Length is the failure mode here: if it does not fit on a
screen I will not act on it. Do not ask me for information you can retrieve yourself,
and if something could not be determined, say so plainly rather than guessing. Add
clear headers to let me know with a single look what part I am seeing in case I am just
searching for something in concrete about the remediation.`;

const TRIAGE_DECISION_PROMPT = `The finding under discussion is the one in the UI context block. If no finding is
present there, ask me for the finding ID before doing anything else.

I want to decide whether this finding is a real risk for my organization, and then
close it out accordingly.

Start by calling load_tools with these names, in one call:
prowler_get_finding_details, prowler_hub_get_check_details, prowler_get_resource,
prowler_get_compliance_overview, prowler_cloud_get_finding_triage,
prowler_cloud_set_finding_triage_status, prowler_cloud_create_finding_triage_note
You do not need search_tools — I am naming the tools directly.

Then work in this order:

1. prowler_get_finding_details — what is being flagged, on which resource.
2. prowler_hub_get_check_details — why the check considers this a problem, and which
   compliance frameworks it maps to.
3. prowler_get_resource — the actual configuration, tags, environment markers and
   exposure signals of the affected resource. This is the evidence that decides the
   question: the check's severity is a label on the rule, not a measure of my risk.
4. prowler_cloud_get_finding_triage — check whether this finding already carries a
   triage decision. If it does, tell me what it is before proposing a new one.
5. prowler_get_compliance_overview — which frameworks my tenant actually tracks. Cross
   this with the frameworks from step 2, and ask me whether those are relevant to me
   before you weigh them heavily.

Then give me a report, in this shape:

- Open with your verdict: is this a real risk for this organization, with a
  confidence percentage on that judgement.
- Follow with the evidence that drove it — what about this specific resource and its
  context makes it exploitable, exposed, or harmless.
- Name anything you could not determine that would change the answer.

Then ask me how I want to proceed, and wait (try to guide me as much as possible in this
cession if you are sure it's a risk then cannot be marked as accepted or as not risk).
Do not write anything to Prowler until I answer. Once I do:

- Real risk → do not fix it here. Tell me to run the fix skill in a separate session,
  and summarize in one line what that fix will involve.
- Risk I tell you I accept → prowler_cloud_set_finding_triage_status to accepted risk,
  then prowler_cloud_create_finding_triage_note containing the reasoning above, so the
  decision is documented for whoever reads this finding next.
- Not a risk at all → prowler_cloud_set_finding_triage_status to false positive, then
  prowler_cloud_create_finding_triage_note explaining why.

Before any call to prowler_cloud_set_finding_triage_status or
prowler_cloud_create_finding_triage_note, state exactly what you are about to set and
on which finding, and let me confirm.`;

const SYSTEMIC_SCOPE_PROMPT = `The finding under discussion is the one in the UI context block. If no finding is
present there, ask me for the finding ID before doing anything else.

I want to know whether this finding is an isolated case or a symptom of something
spread across my organization.

Start by calling load_tools with these names, in one call:
prowler_get_finding_details, prowler_hub_get_check_details,
prowler_hub_get_check_fixer, prowler_list_finding_groups,
prowler_list_finding_group_resources
You do not need search_tools — I am naming the tools directly.

Then work in this order:

1. prowler_get_finding_details — get the check ID behind this finding. Everything below
   keys off it.
2. prowler_hub_get_check_details — the error class: what this rule checks and why it
   matters.
3. prowler_hub_get_check_fixer — if a fixer exists, get it, so you understand what
   remediating a single instance actually involves. Skip if there is none.
4. prowler_list_finding_groups — filter by the check ID from step 1 and sort by failure
   count descending. This aggregates the check across my whole estate in one call:
   how many resources are affected, in which providers, accounts and regions. Do not
   page through individual findings to reconstruct this.
5. prowler_list_finding_group_resources — for the group returned above, list the
   specific resources that are failing.

Then give me a report covering:

- The error class in general: what is failing and why it happens, described once rather
  than repeated per resource.
- The spread: how many resources, across which accounts, regions and providers. Say
  plainly whether this is a one-off or systemic.
- How it affects the organization if left as is.
- Which affected resources look most dangerous and deserve priority, and why — based on
  the resources' actual exposure, not on the check's severity, which is identical for
  all of them.
- The upstream change that prevents the entire class rather than fixing instances one by
  one: an SCP or org policy, an IAM boundary, a Terraform module, a baseline. This is
  the part I most want. If no such systemic change exists, say so and instead give me
  the order in which to work through the resources with the fix skill.

Do not give me a script that mass-mutates my cloud resources. Give me the systemic
change or the prioritized order.`;

export const LIGHTHOUSE_SKILLS = [
  {
    id: LIGHTHOUSE_SKILL_ID.CONTEXTUAL_FIX,
    name: "Contextual Fix",
    description: "Give me the fix for this finding",
    icon: Wrench,
    prompt: CONTEXTUAL_FIX_PROMPT,
    nextSkillId: null,
    enabled: true,
    version: 1,
  },
  {
    id: LIGHTHOUSE_SKILL_ID.TRIAGE_DECISION,
    name: "Triage Decision",
    description: "Is this real, and if not, close it out",
    icon: ClipboardCheck,
    prompt: TRIAGE_DECISION_PROMPT,
    // Triage's "real risk" outcome hands off to the fix skill in a new session.
    nextSkillId: LIGHTHOUSE_SKILL_ID.CONTEXTUAL_FIX,
    enabled: true,
    version: 1,
  },
  {
    id: LIGHTHOUSE_SKILL_ID.SYSTEMIC_SCOPE,
    name: "Systemic Scope",
    description: "Is this one-off or everywhere?",
    icon: Waypoints,
    prompt: SYSTEMIC_SCOPE_PROMPT,
    nextSkillId: null,
    enabled: true,
    version: 1,
  },
  {
    id: LIGHTHOUSE_SKILL_ID.COMPLIANCE_IMPACT,
    name: "Compliance Impact",
    description: "How is this finding affecting my compliance?",
    icon: Scale,
    // Blocked upstream: MCP lacks a compliance-requirements-per-finding tool,
    // so DyR has not authored the final prompt yet.
    prompt: "",
    nextSkillId: null,
    enabled: false,
    version: 1,
  },
] as const satisfies readonly LighthouseSkillDefinition[];
