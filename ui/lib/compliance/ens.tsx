import { ClientAccordionContent } from "@/components/compliance/compliance-accordion/client-accordion-content";
import { ComplianceAccordionRequirementTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-requeriment-title";
import { ComplianceAccordionTitle } from "@/components/compliance/compliance-accordion/compliance-accordion-title";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import { FindingStatus } from "@/components/ui/table/status-finding-badge";
import {
  AttributesData,
  ENSAttributesMetadata,
  Framework,
  Requirement,
  RequirementsData,
  RequirementStatus,
} from "@/types/compliance";

import {
  calculateFrameworkCounters,
  createRequirementsMap,
  findOrCreateCategory,
  findOrCreateControl,
  findOrCreateFramework,
} from "./commons";

export const translateType = (type: string) => {
  if (!type) {
    return "";
  }

  switch (type.toLowerCase()) {
    case "requisito":
      return "Requirement";
    case "recomendacion":
      return "Recommendation";
    case "refuerzo":
      return "Reinforcement";
    case "medida":
      return "Measure";
    default:
      return type;
  }
};

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
    const attrs = attributeItem.attributes?.attributes
      ?.metadata?.[0] as ENSAttributesMetadata;

    if (!attrs) continue;

    // Get corresponding requirement data
    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const frameworkName = attrs.Marco;
    const categoryName = attrs.Categoria;
    const groupControl = attrs.IdGrupoControl;
    const type = attrs.Tipo;
    const description = attributeItem.attributes.description;
    const status = requirementData.attributes.status || "";
    const controlDescription = attrs.DescripcionControl || "";
    const checks = attributeItem.attributes.attributes.check_ids || [];
    const isManual = attrs.ModoEjecucion === "manual";
    const requirementName = id;
    const groupControlLabel = `${groupControl} - ${description}`;

    // Find or create framework using common helper
    const framework = findOrCreateFramework(frameworks, frameworkName);

    // Find or create category using common helper
    const category = findOrCreateCategory(framework.categories, categoryName);

    // Find or create control using common helper
    const control = findOrCreateControl(category.controls, groupControlLabel);

    // Create requirement
    const finalStatus: RequirementStatus = isManual
      ? "MANUAL"
      : (status as RequirementStatus);
    const requirement: Requirement = {
      name: requirementName,
      description: controlDescription,
      status: finalStatus,
      type,
      check_ids: checks,
      pass: finalStatus === "PASS" ? 1 : 0,
      fail: finalStatus === "FAIL" ? 1 : 0,
      manual: finalStatus === "MANUAL" ? 1 : 0,
      nivel: attrs.Nivel || "",
      dimensiones: attrs.Dimensiones || [],
    };

    control.requirements.push(requirement);
  }

  // Calculate counters using common helper
  calculateFrameworkCounters(frameworks);

  return frameworks;
};

export const toAccordionItems = (
  data: Framework[],
  scanId: string | undefined,
): AccordionItemProps[] => {
  return data.map((framework) => {
    return {
      key: framework.name,
      title: (
        <ComplianceAccordionTitle
          label={framework.name}
          pass={framework.pass}
          fail={framework.fail}
          manual={framework.manual}
          isParentLevel={true}
        />
      ),
      content: "",
      items: framework.categories.map((category) => {
        return {
          key: `${framework.name}-${category.name}`,
          title: (
            <ComplianceAccordionTitle
              label={category.name}
              pass={category.pass}
              fail={category.fail}
              manual={category.manual}
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
                      type={requirement.type as string}
                      name={requirement.name}
                      status={requirement.status as FindingStatus}
                    />
                  ),
                  content: (
                    <ClientAccordionContent
                      requirement={requirement}
                      scanId={scanId || ""}
                      framework={framework.name}
                      disableFindings={
                        requirement.check_ids.length === 0 &&
                        requirement.manual === 0
                      }
                    />
                  ),
                };
              }),
              isDisabled:
                control.pass === 0 &&
                control.fail === 0 &&
                control.manual === 0,
            };
          }),
        };
      }),
    };
  });
};
