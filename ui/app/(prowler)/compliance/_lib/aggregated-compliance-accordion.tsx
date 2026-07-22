import type { ReactNode } from "react";

import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import type { AccordionItemProps } from "@/components/shadcn/accordion/Accordion";
import type { FindingStatus } from "@/components/shadcn/table/status-finding-badge";
import type { Control, Framework, Requirement } from "@/types/compliance";

interface AggregatedComplianceAccordionOptions<TExtras> {
  data: Framework[];
  extras: Map<string, TExtras>;
  renderStatus: (extras: TExtras) => ReactNode;
  renderContent: (
    requirement: Requirement,
    extras: TExtras,
    itemKey: string,
  ) => ReactNode;
  missingBreakdownMessage: string;
}

/** Shared mapper-driven hierarchy for provider- and account-axis compliance.
 * Axis adapters supply only the status summary and lazy findings content. */
export const toAggregatedComplianceAccordionItems = <TExtras,>({
  data,
  extras,
  renderStatus,
  renderContent,
  missingBreakdownMessage,
}: AggregatedComplianceAccordionOptions<TExtras>): AccordionItemProps[] => {
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
        <ComplianceAccordionRequirementTitle
          type={requirementType}
          name={rowTitle}
          status={requirement.status as FindingStatus}
          invalidConfig={requirement.invalid_config}
          statusContent={
            requirementExtras ? renderStatus(requirementExtras) : undefined
          }
        />
      ),
      content: requirementExtras ? (
        renderContent(requirement, requirementExtras, itemKey)
      ) : (
        <p key={`content-${itemKey}`} className="text-sm">
          {missingBreakdownMessage}
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
    const groupLabel =
      control.label && control.label !== categoryName
        ? control.label
        : undefined;

    if (groupLabel && control.requirements.length > 1) {
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
          items: control.requirements.map((requirement, requirementIndex) =>
            requirementItem(
              requirement,
              `${baseKey}-req-${requirementIndex}`,
              requirement.name as string,
            ),
          ),
        },
      ];
    }

    return control.requirements.map((requirement, requirementIndex) =>
      requirementItem(
        requirement,
        `${baseKey}-req-${requirementIndex}`,
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
      items: category.controls.flatMap((control, controlIndex) =>
        controlItems(
          control,
          category.name,
          `${frameworkData.name}-${category.name}-c${controlIndex}`,
        ),
      ),
    }));

  const frameworkItems = (frameworkData: Framework): AccordionItemProps[] => {
    const directRequirements =
      (frameworkData as { requirements?: Requirement[] }).requirements ?? [];
    if (directRequirements.length > 0) {
      return directRequirements.map((requirement, requirementIndex) =>
        requirementItem(
          requirement,
          `${frameworkData.name}-req-${requirementIndex}`,
          requirement.name as string,
        ),
      );
    }
    return categoryItems(frameworkData);
  };

  if (data.length > 1) {
    return data.map((frameworkData) => ({
      key: frameworkData.name,
      title: (
        <ComplianceAccordionTitle
          label={frameworkData.name}
          pass={frameworkData.pass}
          fail={frameworkData.fail}
          manual={frameworkData.manual}
          isParentLevel
        />
      ),
      content: "",
      items: frameworkItems(frameworkData),
    }));
  }

  return data.flatMap(frameworkItems);
};
