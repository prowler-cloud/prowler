import { AccordionItemProps } from "@/components/ui/accordion/Accordion";
import HorizontalSplitBar from "@/components/ui/chart/horizontal-split-chart";
import { Category, Check, Control, Framework } from "@/types/compliance/ens";

export const mapComplianceData = (rawData: any) => {
  const requirements = rawData.attributes?.requirements || {};
  const frameworkMap: Map<string, Framework> = new Map();

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

    const groupControlLabel = description
      ? `${groupControl} - ${description}`
      : groupControl;

    const controlKey = `${groupControl}-${description}`;

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

    if (!categoryObj.controls.has(controlKey)) {
      categoryObj.controls.set(controlKey, {
        label: groupControlLabel,
        tipo: type,
        pass: 0,
        fail: 0,
        manual: 0,
        checks: [] as Check[],
      });
    }

    const controlObj = categoryObj.controls.get(controlKey)!;

    for (const checkName in checks) {
      const rawStatus = checks[checkName];

      const checkExists = controlObj.checks.some(
        (check) => check.checkName === checkName,
      );

      if (!checkExists) {
        const status = rawStatus === null ? "PASS" : rawStatus;

        controlObj.checks.push({
          checkName,
          status: status,
        });

        if (status === "PASS" || rawStatus === null) {
          controlObj.pass++;
          categoryObj.pass++;
          frameworkObj.pass++;
        } else if (status === "FAIL") {
          controlObj.fail++;
          categoryObj.fail++;
          frameworkObj.fail++;
        } else if (status === "MANUAL") {
          controlObj.manual++;
          categoryObj.manual++;
          frameworkObj.manual++;
        }
      }
    }
  }

  return Array.from(frameworkMap.values()).map((framework) => ({
    name: framework.name,
    pass: framework.pass,
    fail: framework.fail,
    manual: framework.manual,
    categories: Array.from(framework.categories.values()).map((category) => ({
      name: category.name,
      pass: category.pass,
      fail: category.fail,
      manual: category.manual,
      controls: Array.from(category.controls.values()),
    })),
  }));
};

const getStatusEmoji = (status: string) => {
  if (status === "PASS") return "✅";
  if (status === "FAIL") return "❌";
  if (status === "MANUAL") return "🖐";
  return "✅";
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
      title: renderTitle(framework.name, framework.pass, framework.fail),
      content: "",
      items: framework.categories.map((category: any) => {
        return {
          key: `${framework.name}-${category.name}`,
          title: renderTitle(category.name, category.pass, category.fail),
          content: "",
          items: category.controls.map((control: any, i: number) => {
            return {
              key: `${framework.name}-${category.name}-control-${i}`,
              title: renderTitle(control.label, control.pass, control.fail),
              content: renderTable(control.checks, control.tipo),
              items: [],
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

const renderTitle = (label: string, pass: number, fail: number) => {
  return (
    <div className="flex w-full items-center justify-between">
      <span className="w-1/2 uppercase">{label}</span>
      <div className="w-1/2">
        {pass === 0 && fail === 0 ? (
          <p className="text-center text-sm text-default-500">
            Manual requirement
          </p>
        ) : (
          <HorizontalSplitBar
            valueA={pass}
            valueB={fail}
            tooltipContentA="Passed"
            tooltipContentB="Failed"
            showZero={false}
            ratio={2}
            minBarWidth={15}
          />
        )}
      </div>
    </div>
  );
};

// Todo: change for finding table calling the api with the filter[check_id__in] and filter[scan] which is the scan id

const renderTable = (checks: any[], tipo: string) => {
  const translatedType = translateType(tipo);

  return (
    <div className="mt-2">
      <div className="mb-2">
        <span className="font-semibold">Type:</span> {translatedType}
      </div>
      <table className="w-full border text-left text-sm">
        <thead>
          <tr className="border-b bg-gray-50">
            <th className="p-2">Check ID</th>
            <th className="p-2">Status</th>
          </tr>
        </thead>
        <tbody>
          {checks.map((check, i) => (
            <tr key={i} className="border-b">
              <td className="p-2">{check.checkName}</td>
              <td className="p-2 capitalize">
                {getStatusEmoji(check.status)} &nbsp;{" "}
                {check.status === null ? "PASS" : check.status}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
