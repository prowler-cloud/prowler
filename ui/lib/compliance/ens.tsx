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
  RequirementItemData,
  RequirementsData,
  RequirementStatus,
} from "@/types/compliance";

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
  const requirements = requirementsData?.data || [];

  // Create a map for quick lookup of requirements by id
  const requirementsMap = new Map<string, RequirementItemData>();
  requirements.forEach((req: RequirementItemData) => {
    requirementsMap.set(req.id, req);
  });

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

    // Find or create framework
    let framework = frameworks.find((f) => f.name === frameworkName);
    if (!framework) {
      framework = {
        name: frameworkName,
        pass: 0,
        fail: 0,
        manual: 0,
        categories: [],
      };
      frameworks.push(framework);
    }

    // Find or create category
    let category = framework.categories.find((c) => c.name === categoryName);
    if (!category) {
      category = {
        name: categoryName,
        pass: 0,
        fail: 0,
        manual: 0,
        controls: [],
      };
      framework.categories.push(category);
    }

    // Find or create control
    let control = category.controls.find((c) => c.label === groupControlLabel);
    if (!control) {
      control = {
        label: groupControlLabel,
        pass: 0,
        fail: 0,
        manual: 0,
        requirements: [],
      };
      category.controls.push(control);
    }

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

  // Calculate counters
  frameworks.forEach((framework) => {
    framework.pass = 0;
    framework.fail = 0;
    framework.manual = 0;

    framework.categories.forEach((category) => {
      category.pass = 0;
      category.fail = 0;
      category.manual = 0;

      category.controls.forEach((control) => {
        control.pass = 0;
        control.fail = 0;
        control.manual = 0;

        control.requirements.forEach((requirement) => {
          if (requirement.status === "MANUAL") {
            control.manual++;
          } else if (requirement.status === "PASS") {
            control.pass++;
          } else if (requirement.status === "FAIL") {
            control.fail++;
          }
        });

        category.pass += control.pass;
        category.fail += control.fail;
        category.manual += control.manual;
      });

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
