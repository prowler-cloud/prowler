import { Chip } from "@nextui-org/react";

import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import {
  Category,
  Control,
  Framework,
  Requirement,
} from "@/types/compliance/ens";

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

const getStatusEmoji = (status: string) => {
  if (status === "PASS") return "✅";
  if (status === "FAIL") return "❌";
  if (status === "MANUAL") return "🖐";
  return "";
};

const translateType = (tipo: string) => {
  switch (tipo.toLowerCase()) {
    case "requisito":
      return "Requirement";
    case "recomendacion":
      return "Recommendation";
    case "refuerzo":
      return "Reinforcement";
    case "medida":
      return "Measure";
    default:
      return tipo;
  }
};

export const toAccordionItems = (data: any[]): AccordionItemProps[] => {
  return data.map((framework) => {
    return {
      key: framework.name,
      title: renderTitle(
        framework.name,
        framework.pass,
        framework.fail,
        framework.manual,
      ),
      content: "",
      items: framework.categories.map((category: any) => {
        return {
          key: `${framework.name}-${category.name}`,
          title: renderTitle(
            category.name,
            category.pass,
            category.fail,
            category.manual,
          ),
          content: "",
          items: category.controls.map((control: any, i: number) => {
            return {
              key: `${framework.name}-${category.name}-control-${i}`,
              title: renderTitle(
                control.label,
                control.pass,
                control.fail,
                control.manual,
              ),
              content: "",
              items: control.requirements.map((requirement: any, j: number) => {
                return {
                  key: `${framework.name}-${category.name}-control-${i}-req-${j}`,
                  title: renderTitle(
                    requirement.name,
                    requirement.pass,
                    requirement.fail,
                    requirement.manual,
                  ),
                  content: renderTable(requirement),
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

const renderTitle = (
  label: string,
  pass: number,
  fail: number,
  manual: number = 0,
) => {
  // Determine if it's a requirement title (level 4), control (level 3) or higher level
  // Requirement names are like "op.exp.5.aws.cm.1"
  const isRequirementLevel = /\.\w+\.\d+$/.test(label); // Checks if it ends with .word.number
  const isControlLevel = label.includes(" - ") && !isRequirementLevel;

  let prefix = "Requirements";
  if (isRequirementLevel) {
    prefix = "Findings";
  } else if (isControlLevel) {
    prefix = "Requirements";
  }

  return (
    <div className="flex flex-col flex-wrap items-start justify-between gap-1 md:flex-row md:items-center md:gap-0">
      <div className="w-1/2 overflow-hidden md:min-w-0">
        <span
          className="block w-full overflow-hidden truncate text-ellipsis pr-2 uppercase"
          title={label}
        >
          {label}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <div className="hidden lg:block">
          {(pass > 0 || fail > 0 || manual > 0) && (
            <span className="mr-1 whitespace-nowrap text-xs font-medium text-gray-600">
              {prefix}:
            </span>
          )}
        </div>

        <Chip
          size="sm"
          color="success"
          variant="flat"
          className="whitespace-nowrap"
        >
          Pass: {pass}
        </Chip>

        <Chip
          size="sm"
          color="danger"
          variant="flat"
          className="whitespace-nowrap"
        >
          Fail: {fail}
        </Chip>

        <Chip
          size="sm"
          color="default"
          variant="bordered"
          className="whitespace-nowrap"
        >
          Manual: {manual}
        </Chip>
      </div>
    </div>
  );
};

const renderTable = (requirement: any) => {
  const translatedType = translateType(requirement.tipo);
  const checks = requirement.checks || [];

  return (
    <div className="mt-2 w-full overflow-x-auto">
      <div className="mb-2">
        <span className="font-semibold">Type:</span> {translatedType}
      </div>
      <div className="mb-2">
        <span className="font-semibold">Description:</span>{" "}
        {requirement.description}
      </div>
      {checks.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-full border text-left text-sm">
            <thead>
              <tr className="border-b bg-gray-50">
                <th className="p-2">Check ID</th>
                <th className="p-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {checks.map((check: any, i: number) => (
                <tr key={i} className="border-b">
                  <td className="break-all p-2">{check.checkName}</td>
                  <td className="whitespace-nowrap p-2 capitalize">
                    {getStatusEmoji(check.status)} &nbsp; {check.status}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
