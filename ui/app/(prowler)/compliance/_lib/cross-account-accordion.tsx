import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import { InfoTooltip } from "@/components/shadcn/info-field/info-field";
import {
  type FindingStatus,
  StatusFindingBadge,
} from "@/components/shadcn/table/status-finding-badge";
import { INVALID_CONFIG_NOTE } from "@/lib/compliance/commons";
import type { Control, Framework, Requirement } from "@/types/compliance";

import { CrossAccountRequirementContent } from "../_components/cross-account-requirement-content";
import { RequirementAccountChips } from "../_components/requirement-account-chips";
import type {
  CrossAccountAccountRef,
  CrossAccountRequirementExtras,
} from "../_types";

/**
 * Accordion assembly for the cross-account detail — the account-axis sibling
 * of `toCrossProviderAccordionItems` (same section key scheme, so `?section=`
 * deep links behave identically). Each requirement's status is shown once,
 * on the title row: via the per-account chips when a breakdown exists, or a
 * single roll-up badge as a fallback. `extras` is the map produced by
 * `buildAccountExtrasMap`, keyed by the mapper-composed requirement name.
 *
 * Row titles and hierarchy mirror what each mapper's OWN per-scan
 * `toAccordionItems` renders, so a framework looks the same here as in the
 * Single Scan view:
 * - CSA/CIS-Controls/DORA-style mappers put every requirement (already
 *   richly named `id - title`) under one control labeled like its category
 *   → flatten to requirement rows.
 * - The CIS mapper creates one control PER requirement whose label carries
 *   the full `id - description` while `requirement.name` is the bare id
 *   → use the control label as the row title.
 * - ENS-style mappers group frameworks (marcos) above categories and
 *   several requirements under a labeled control → keep both extra levels,
 *   like per-scan does, and show each requirement's type chip
 *   (requisito/recomendación/refuerzo).
 */
export const toCrossAccountAccordionItems = (
  data: Framework[],
  extras: Map<string, CrossAccountRequirementExtras>,
  framework: string,
  accountMeta: CrossAccountAccountRef[],
): AccordionItemProps[] => {
  const requirementItem = (
    requirement: Requirement,
    itemKey: string,
    rowTitle: string,
  ): AccordionItemProps => {
    const requirementExtras = extras.get(requirement.name as string);
    const requirementType =
      typeof requirement.type === "string" ? requirement.type : "";

    return {
      key: itemKey,
      title: (
        <div className="flex w-full items-center justify-between gap-3">
          {/* Same left-side composition as the per-scan
              ComplianceAccordionRequirementTitle (type chip + name +
              invalid-config note); only the right side differs (per-account
              chips instead of one status badge). */}
          <div className="flex min-w-0 items-center gap-2">
            {requirementType && (
              <span className="bg-button-primary/10 text-button-primary rounded-md px-2 py-0.5 text-xs font-medium">
                {requirementType}
              </span>
            )}
            <span className="min-w-0 truncate">{rowTitle}</span>
            {requirement.invalid_config && (
              <InfoTooltip content={INVALID_CONFIG_NOTE} />
            )}
          </div>
          {requirementExtras ? (
            <RequirementAccountChips
              accounts={requirementExtras.accounts}
              accountMeta={accountMeta}
            />
          ) : (
            <StatusFindingBadge status={requirement.status as FindingStatus} />
          )}
        </div>
      ),
      // Explicit key on the content element, matching the per-scan mappers
      // (csa.tsx et al.): these elements travel to the client inside the
      // serialized `items` array, where React's Flight layer warns about
      // un-keyed elements ("Each child in a list…").
      content: requirementExtras ? (
        <CrossAccountRequirementContent
          key={`content-${itemKey}`}
          requirement={requirement}
          extras={requirementExtras}
          accountMeta={accountMeta}
          framework={framework}
        />
      ) : (
        <p key={`content-${itemKey}`} className="text-sm">
          No per-account breakdown is available for this requirement.
        </p>
      ),
      items: [],
    };
  };

  const controlItems = (
    control: Control,
    categoryName: string,
    baseKey: string,
  ): AccordionItemProps[] => {
    // A label that just repeats the category (the flat-mapper convention)
    // carries no information; a distinct one is the mapper's richer title.
    const groupLabel =
      control.label && control.label !== categoryName
        ? control.label
        : undefined;

    if (groupLabel && control.requirements.length > 1) {
      // ENS-style group: keep the control as its own accordion level, the
      // way that mapper's per-scan toAccordionItems renders it.
      return [
        {
          key: baseKey,
          title: (
            <ComplianceAccordionTitle
              label={groupLabel}
              pass={control.pass}
              fail={control.fail}
              manual={control.manual}
            />
          ),
          content: "",
          items: control.requirements.map((requirement, reqIndex) =>
            requirementItem(
              requirement,
              `${baseKey}-req-${reqIndex}`,
              requirement.name as string,
            ),
          ),
        },
      ];
    }

    return control.requirements.map((requirement, reqIndex) =>
      requirementItem(
        requirement,
        `${baseKey}-req-${reqIndex}`,
        // Single-requirement controls (CIS style) carry the full
        // `id - description` in the control label while requirement.name is
        // the bare id — prefer the richer title, like the per-scan view.
        (groupLabel ?? requirement.name) as string,
      ),
    );
  };

  const categoryItems = (frameworkData: Framework): AccordionItemProps[] =>
    frameworkData.categories.map((category) => ({
      key: `${frameworkData.name}-${category.name}`,
      title: (
        <ComplianceAccordionTitle
          label={category.name}
          pass={category.pass}
          fail={category.fail}
          manual={category.manual}
          isParentLevel={data.length === 1}
        />
      ),
      content: "",
      // The control index participates in the key: a category can hold
      // several controls whose requirement lists all start at index 0, so
      // keying on the requirement index alone collides across controls
      // (React "two children with the same key").
      items: category.controls.flatMap((control, controlIndex) =>
        controlItems(
          control,
          category.name,
          `${frameworkData.name}-${category.name}-c${controlIndex}`,
        ),
      ),
    }));

  const frameworkItems = (frameworkData: Framework): AccordionItemProps[] => {
    // Flat generic-mapper structure (e.g. GDPR): requirements hang directly
    // off the framework with no categories — that mapper's per-scan
    // toAccordionItems renders them as top-level rows, so mirror it.
    const directRequirements =
      (frameworkData as { requirements?: Requirement[] }).requirements ?? [];
    if (directRequirements.length > 0) {
      return directRequirements.map((requirement, reqIndex) =>
        requirementItem(
          requirement,
          `${frameworkData.name}-req-${reqIndex}`,
          requirement.name as string,
        ),
      );
    }
    return categoryItems(frameworkData);
  };

  // Multi-framework data (ENS marcos: Operacional, Organizativo…) keeps the
  // framework as the top accordion level, exactly like that mapper's own
  // per-scan toAccordionItems; single-framework data starts at categories.
  if (data.length > 1) {
    return data.map((frameworkData) => ({
      key: frameworkData.name,
      title: (
        <ComplianceAccordionTitle
          label={frameworkData.name}
          pass={frameworkData.pass}
          fail={frameworkData.fail}
          manual={frameworkData.manual}
          isParentLevel={true}
        />
      ),
      content: "",
      items: frameworkItems(frameworkData),
    }));
  }

  return data.flatMap(frameworkItems);
};
