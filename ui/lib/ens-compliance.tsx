import { ClientAccordionContent } from "@/components/compliance/client-accordion-content";
import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import {
  Category,
  Control,
  Framework,
  Requirement,
} from "@/types/compliance/ens";

import { ComplianceAccordionTitle } from "../components/compliance/compliance-accordion-title";

export const mapComplianceData = (rawData: any) => {
  const requirements = rawData.attributes?.requirements || {};
  const frameworkMap: Map<string, Framework> = new Map();

  // First step: create the entire hierarchical structure and add the requirements
  for (const key in requirements) {
    const item = requirements[key];
    const attrs = item.attributes?.[0];
    if (!attrs) continue;

    const framework = attrs.Marco;
    const category = attrs.Categoria;
    const groupControl = attrs.IdGrupoControl;
    const type = attrs.Tipo;
    const checks = item.checks || {};
    const description = item.description;
    const status = item.status || "";
    const checksStatus = item.checks_status || {
      pass: 0,
      fail: 0,
      manual: 0,
      total: 0,
    };
    // A requirement is manual if it has no checks or if its execution mode is manual
    const isManual =
      Object.keys(checks).length === 0 || attrs.ModoEjecucion === "manual";
    const requirementName = item.name || key;
    const controlDescription = attrs.DescripcionControl || "";

    // The control group is identified by its ID and general description
    const groupControlLabel = `${groupControl} - ${description}`;
    const controlKey = `${groupControl}-${description}`;

    // Create framework if it doesn't exist
    if (!frameworkMap.has(framework)) {
      frameworkMap.set(framework, {
        name: framework,
        pass: 0,
        fail: 0,
        manual: 0,
        categories: new Map<string, Category>(),
      });
    }

    const frameworkObj = frameworkMap.get(framework)!;

    // Create category if it doesn't exist
    if (!frameworkObj.categories.has(category)) {
      frameworkObj.categories.set(category, {
        name: category,
        pass: 0,
        fail: 0,
        manual: 0,
        controls: new Map<string, Control>(),
      });
    }

    const categoryObj = frameworkObj.categories.get(category)!;

    // Create control if it doesn't exist
    if (!categoryObj.controls.has(controlKey)) {
      categoryObj.controls.set(controlKey, {
        label: groupControlLabel,
        tipo: type,
        pass: 0,
        fail: 0,
        manual: 0,
        requirements: new Map<string, Requirement>(),
      });
    }

    const controlObj = categoryObj.controls.get(controlKey)!;

    // Create requirement if it doesn't exist
    if (!controlObj.requirements.has(requirementName)) {
      controlObj.requirements.set(requirementName, {
        name: requirementName,
        description: controlDescription,
        status: isManual ? "MANUAL" : status, // Force MANUAL status for requirements without checks
        tipo: type,
        checks: [],
        pass: checksStatus.pass || 0,
        fail: checksStatus.fail || 0,
        manual: isManual ? 1 : checksStatus.manual || 0, // Mark as manual if it has no checks
      });
    }

    const requirementObj = controlObj.requirements.get(requirementName)!;

    // Add checks to the requirement
    if (!isManual) {
      for (const checkName in checks) {
        const rawStatus = checks[checkName];
        const status = rawStatus === null ? "No findings" : rawStatus;

        requirementObj.checks.push({
          checkName,
          status: status,
        });
      }
    }
  }

  // Second step: calculate counters at higher levels based on requirements
  const frameworks = Array.from(frameworkMap.values());
  for (const framework of frameworks) {
    // Reset framework counters
    framework.pass = 0;
    framework.fail = 0;
    framework.manual = 0;

    const categories = Array.from(framework.categories.values());
    for (const category of categories) {
      // Reset category counters
      category.pass = 0;
      category.fail = 0;
      category.manual = 0;

      const controls = Array.from(category.controls.values());
      for (const control of controls) {
        // Reset control counters
        control.pass = 0;
        control.fail = 0;
        control.manual = 0;

        // Sum requirements to get control counters
        const requirements = Array.from(control.requirements.values());
        for (const requirement of requirements) {
          // Add to control based on requirement status
          // If it has no checks or is of manual type, count it as a manual requirement
          const noChecks = requirement.checks.length === 0;

          if (noChecks || requirement.status === "MANUAL") {
            control.manual++;
          } else if (requirement.status === "PASS") {
            control.pass++;
          } else if (requirement.status === "FAIL") {
            control.fail++;
          } else {
            control.manual++;
          }
        }

        // Add to category
        category.pass += control.pass;
        category.fail += control.fail;
        category.manual += control.manual;
      }

      // Add to framework
      framework.pass += category.pass;
      framework.fail += category.fail;
      framework.manual += category.manual;
    }
  }

  // Transform maps to arrays for output
  return frameworks.map((framework) => ({
    name: framework.name,
    pass: framework.pass,
    fail: framework.fail,
    manual: framework.manual,
    categories: Array.from(framework.categories.values()).map((category) => ({
      name: category.name,
      pass: category.pass,
      fail: category.fail,
      manual: category.manual,
      controls: Array.from(category.controls.values()).map((control) => ({
        label: control.label,
        tipo: control.tipo,
        pass: control.pass,
        fail: control.fail,
        manual: control.manual,
        requirements: Array.from(control.requirements.values()),
      })),
    })),
  }));
};

export const toAccordionItems = (
  data: any[],
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
        />
      ),
      content: "",
      items: framework.categories.map((category: any) => {
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
          items: category.controls.map((control: any, i: number) => {
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
              items: control.requirements.map((requirement: any, j: number) => {
                const itemKey = `${framework.name}-${category.name}-control-${i}-req-${j}`;

                return {
                  key: itemKey,
                  title: (
                    <ComplianceAccordionTitle
                      label={requirement.name}
                      pass={requirement.pass}
                      fail={requirement.fail}
                      manual={requirement.manual}
                    />
                  ),
                  content: (
                    <ClientAccordionContent
                      requirement={requirement}
                      scanId={scanId || ""}
                    />
                  ),
                  items: [],
                  isDisabled:
                    requirement.checks.length === 0 && requirement.manual === 0,
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
