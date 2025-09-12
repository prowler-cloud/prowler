import {
  CategoryData,
  FailedSection,
  Framework,
  Requirement,
  RequirementItemData,
  RequirementsData,
  RequirementStatus,
} from "@/types/compliance";

export const updateCounters = (
  target: { pass: number; fail: number; manual: number },
  status: RequirementStatus,
) => {
  if (status === "MANUAL") {
    target.manual++;
  } else if (status === "PASS") {
    target.pass++;
  } else if (status === "FAIL") {
    target.fail++;
  }
};

export const getTopFailedSections = (
  mappedData: Framework[],
): FailedSection[] => {
  const failedSectionMap = new Map();

  mappedData.forEach((framework) => {
    framework.categories.forEach((category) => {
      category.controls.forEach((control) => {
        control.requirements.forEach((requirement) => {
          if (requirement.status === "FAIL") {
            const sectionName = category.name;

            if (!failedSectionMap.has(sectionName)) {
              failedSectionMap.set(sectionName, { total: 0, types: {} });
            }

            const sectionData = failedSectionMap.get(sectionName);
            sectionData.total += 1;

            const type = requirement.type || "Fails";

            sectionData.types[type as string] =
              (sectionData.types[type as string] || 0) + 1;
          }
        });
      });
    });
  });

  // Convert in descending order and slice top 5
  return Array.from(failedSectionMap.entries())
    .map(([name, data]) => ({ name, ...data }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 5); // Top 5
};

export const calculateCategoryHeatmapData = (
  complianceData: Framework[],
): CategoryData[] => {
  if (!complianceData?.length) {
    return [];
  }

  try {
    const categoryMap = new Map<
      string,
      { pass: number; fail: number; manual: number }
    >();

    // Aggregate data by category
    complianceData.forEach((framework) => {
      framework.categories.forEach((category) => {
        const existing = categoryMap.get(category.name) || {
          pass: 0,
          fail: 0,
          manual: 0,
        };
        categoryMap.set(category.name, {
          pass: existing.pass + category.pass,
          fail: existing.fail + category.fail,
          manual: existing.manual + category.manual,
        });
      });
    });

    const categoryData: CategoryData[] = Array.from(categoryMap.entries()).map(
      ([name, stats]) => {
        const totalRequirements = stats.pass + stats.fail + stats.manual;
        const failurePercentage =
          totalRequirements > 0
            ? Math.round((stats.fail / totalRequirements) * 100)
            : 0;

        return {
          name,
          failurePercentage,
          totalRequirements,
          failedRequirements: stats.fail,
        };
      },
    );

    const filteredData = categoryData
      .filter((category) => category.totalRequirements > 0)
      .sort((a, b) => b.failurePercentage - a.failurePercentage)
      .slice(0, 9); // Show top 9 categories

    return filteredData;
  } catch (error) {
    console.error("Error calculating category heatmap data:", error);
    return [];
  }
};

export const createRequirementsMap = (
  requirementsData: RequirementsData,
): Map<string, RequirementItemData> => {
  const requirementsMap = new Map<string, RequirementItemData>();
  const requirements = requirementsData?.data || [];
  requirements.forEach((req: RequirementItemData) => {
    requirementsMap.set(req.id, req);
  });
  return requirementsMap;
};

export const findOrCreateFramework = (
  frameworks: Framework[],
  frameworkName: string,
): Framework => {
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
  return framework;
};

export const findOrCreateCategory = (
  categories: any[],
  categoryName: string,
) => {
  let category = categories.find((c) => c.name === categoryName);
  if (!category) {
    category = {
      name: categoryName,
      pass: 0,
      fail: 0,
      manual: 0,
      controls: [],
    };
    categories.push(category);
  }
  return category;
};

export const findOrCreateControl = (controls: any[], controlLabel: string) => {
  let control = controls.find((c) => c.label === controlLabel);
  if (!control) {
    control = {
      label: controlLabel,
      pass: 0,
      fail: 0,
      manual: 0,
      requirements: [],
    };
    controls.push(control);
  }
  return control;
};

export const calculateFrameworkCounters = (frameworks: Framework[]) => {
  frameworks.forEach((framework) => {
    // Reset framework counters
    framework.pass = 0;
    framework.fail = 0;
    framework.manual = 0;

    // Handle flat structure (requirements directly in framework)
    const directRequirements = (framework as any).requirements || [];
    if (directRequirements.length > 0) {
      directRequirements.forEach((requirement: Requirement) => {
        updateCounters(framework, requirement.status);
      });
      return;
    }

    // Handle hierarchical structure (categories -> controls -> requirements)
    framework.categories.forEach((category) => {
      category.pass = 0;
      category.fail = 0;
      category.manual = 0;

      category.controls.forEach((control) => {
        control.pass = 0;
        control.fail = 0;
        control.manual = 0;

        control.requirements.forEach((requirement) => {
          updateCounters(control, requirement.status);
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
};
