import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import { FindingStatus } from "@/components/ui/table/status-finding-badge";
import {
  AttributesData,
  Framework,
  Requirement,
  REQUIREMENT_STATUS,
  RequirementsData,
  RequirementStatus,
  ThreatAttributesMetadata,
} from "@/types/compliance";

import {
  createRequirementsMap,
  findOrCreateCategory,
  findOrCreateControl,
  findOrCreateFramework,
  updateCounters,
} from "./commons";

export const mapComplianceData = (
  attributesData: AttributesData,
  requirementsData: RequirementsData,
): Framework[] => {
  const attributes = attributesData?.data || [];
  const requirementsMap = createRequirementsMap(requirementsData);
  const frameworks: Framework[] = [];

  // Process attributes and merge with requirements data
  for (const attributeItem of attributes) {
    const id = attributeItem.id;
    const metadataArray = attributeItem.attributes?.attributes
      ?.metadata as unknown as ThreatAttributesMetadata[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    // Get corresponding requirement data
    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attributeItem.attributes.framework;
    const sectionName = attrs.Section;
    const subSectionName = attrs.SubSection;
    const title = attrs.Title;
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status || "";
    const checks = attributeItem.attributes.attributes.check_ids || [];
    const requirementName = id;
    const levelOfRisk = attrs.LevelOfRisk;
    const weight = attrs.Weight;
    const attributeDescription = attrs.AttributeDescription;
    const additionalInformation = attrs.AdditionalInformation;
    const passedFindings = requirementData.attributes.passed_findings || 0;
    const totalFindings = requirementData.attributes.total_findings || 0;

    // Calculate score: if PASS = levelOfRisk * weight, if FAIL = 0
    const score = status === REQUIREMENT_STATUS.PASS ? levelOfRisk * weight : 0;

    // Find or create framework using common helper
    const framework = findOrCreateFramework(frameworks, frameworkName);

    // Find or create category (Section) using common helper
    const category = findOrCreateCategory(framework.categories, sectionName);

    // Find or create control (SubSection) using common helper
    const control = findOrCreateControl(category.controls, subSectionName);

    // Create requirement
    const finalStatus: RequirementStatus = status as RequirementStatus;
    const requirement: Requirement = {
      name: requirementName,
      description: description,
      status: finalStatus,
      check_ids: checks,
      pass: finalStatus === REQUIREMENT_STATUS.PASS ? 1 : 0,
      fail: finalStatus === REQUIREMENT_STATUS.FAIL ? 1 : 0,
      manual: finalStatus === REQUIREMENT_STATUS.MANUAL ? 1 : 0,
      title: title,
      levelOfRisk: levelOfRisk,
      weight: weight,
      score: score,
      attributeDescription: attributeDescription,
      additionalInformation: additionalInformation,
      passedFindings: passedFindings,
      totalFindings: totalFindings,
    };

    control.requirements.push(requirement);
  }

  // Calculate counters and percentualScore (Threat-specific logic)
  frameworks.forEach((framework) => {
    framework.pass = 0;
    framework.fail = 0;
    framework.manual = 0;

    framework.categories.forEach((category) => {
      category.pass = 0;
      category.fail = 0;
      category.manual = 0;

      // Calculate ThreatScore using the new formula
      let numerator = 0;
      let denominator = 0;
      let hasFindings = false;

      category.controls.forEach((control) => {
        control.pass = 0;
        control.fail = 0;
        control.manual = 0;

        control.requirements.forEach((requirement) => {
          updateCounters(control, requirement.status);

          // Extract values for ThreatScore calculation
          const pass_i = (requirement.passedFindings as number) || 0;
          const total_i = (requirement.totalFindings as number) || 0;

          // Skip if no findings (avoid division by zero)
          if (total_i === 0) return;

          hasFindings = true;
          const rate_i = pass_i / total_i;
          const weight_i = (requirement.weight as number) || 1;
          const levelOfRisk = (requirement.levelOfRisk as number) || 0;

          // Map levelOfRisk to risk factor (rfac_i)
          // Formula: rfac_i = 1 + (k * levelOfRisk) where k = 0.25
          const rfac_i = 1 + 0.25 * levelOfRisk;

          // Accumulate weighted values
          numerator += rate_i * total_i * weight_i * rfac_i;
          denominator += total_i * weight_i * rfac_i;
        });

        category.pass += control.pass;
        category.fail += control.fail;
        category.manual += control.manual;
      });

      // Calculate ThreatScore (percentualScore) for this section
      // If no findings exist, consider it 100% (PASS)
      const percentualScore = !hasFindings
        ? 100
        : denominator > 0
          ? (numerator / denominator) * 100
          : 0;

      // Add percentualScore to category (we can extend the type or use a custom property)
      (category as any).percentualScore =
        Math.round(percentualScore * 100) / 100; // Round to 2 decimal places

      framework.pass += category.pass;
      framework.fail += category.fail;
      framework.manual += category.manual;
    });
  });

  return frameworks;
};

export const toAccordionItems = (
  data: Framework[],
  scanId: string | undefined,
): AccordionItemProps[] => {
  return data.flatMap((framework) =>
    framework.categories.map((category) => {
      const percentualScore = (category as any).percentualScore || 0;

      return {
        key: `${framework.name}-${category.name}`,
        title: (
          <ComplianceAccordionTitle
            label={`${category.name} - ${percentualScore}%`}
            pass={category.pass}
            fail={category.fail}
            manual={category.manual}
            isParentLevel={true}
          />
        ),
        content: "",
        items: category.controls.map((control, i: number) => {
          return {
            key: `${framework.name}-${category.name}-control-${i}`,
            title: (
              <ComplianceAccordionTitle
                label={control.label}
                pass={control.pass}
                fail={control.fail}
                manual={control.manual}
              />
            ),
            content: "",
            items: control.requirements.map((requirement, j: number) => {
              const itemKey = `${framework.name}-${category.name}-control-${i}-req-${j}`;

              return {
                key: itemKey,
                title: (
                  <ComplianceAccordionRequirementTitle
                    type=""
                    name={`${requirement.name} - ${requirement.title || requirement.description}`}
                    status={requirement.status as FindingStatus}
                  />
                ),
                content: (
                  <ClientAccordionContent
                    key={`content-${itemKey}`}
                    requirement={requirement}
                    scanId={scanId || ""}
                    framework={framework.name}
                    disableFindings={
                      requirement.check_ids.length === 0 &&
                      requirement.manual === 0
                    }
                  />
                ),
                items: [],
              };
            }),
            isDisabled:
              control.pass === 0 && control.fail === 0 && control.manual === 0,
          };
        }),
      };
    }),
  );
};
