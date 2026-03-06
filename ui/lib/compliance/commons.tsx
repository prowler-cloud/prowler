import {
  Category,
  CategoryData,
  Control,
  FailedSection,
  Framework,
  REQUIREMENT_STATUS,
  RequirementItemData,
  RequirementsData,
  RequirementStatus,
  TOP_FAILED_DATA_TYPE,
  TopFailedDataType,
  TopFailedResult,
} from "@/types/compliance";

// Type for the internal map used in getTopFailedSections
interface FailedSectionData {
  total: number;
  types: Record<string, number>;
}

/**
 * Builds the TopFailedResult from the accumulated map data
 */
const buildTopFailedResult = (
  map: Map<string, FailedSectionData>,
  type: TopFailedDataType,
): TopFailedResult => ({
  items: Array.from(map.entries())
    .map(([name, data]): FailedSection => ({ name, ...data }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 5),
  type,
});

/**
 * Checks if the framework uses a flat structure (requirements directly on framework)
 * vs hierarchical structure (categories -> controls -> requirements)
 */
const hasFlatStructure = (frameworks: Framework[]): boolean =>
  frameworks.some(
    (framework) =>
      (framework.requirements?.length ?? 0) > 0 &&
      framework.categories.length === 0,
  );

/**
 * Increments the failed count for a given name in the map
 */
const incrementFailedCount = (
  map: Map<string, FailedSectionData>,
  name: string,
  type: string,
): void => {
  if (!map.has(name)) {
    map.set(name, { total: 0, types: {} });
  }
  const data = map.get(name)!;
  data.total += 1;
  data.types[type] = (data.types[type] || 0) + 1;
};

export const updateCounters = (
  target: { pass: number; fail: number; manual: number },
  status: RequirementStatus,
) => {
  if (status === REQUIREMENT_STATUS.MANUAL) {
    target.manual++;
  } else if (status === REQUIREMENT_STATUS.PASS) {
    target.pass++;
  } else if (status === REQUIREMENT_STATUS.FAIL) {
    target.fail++;
  }
};

export const getTopFailedSections = (
  mappedData: Framework[],
): TopFailedResult => {
  const failedSectionMap = new Map<string, FailedSectionData>();

  if (hasFlatStructure(mappedData)) {
    // Handle flat structure: count failed requirements directly
    mappedData.forEach((framework) => {
      const directRequirements = framework.requirements ?? [];

      directRequirements.forEach((requirement) => {
        if (requirement.status === REQUIREMENT_STATUS.FAIL) {
          const type =
            typeof requirement.type === "string" ? requirement.type : "Fails";
          incrementFailedCount(failedSectionMap, requirement.name, type);
        }
      });
    });

    return buildTopFailedResult(
      failedSectionMap,
      TOP_FAILED_DATA_TYPE.REQUIREMENTS,
    );
  }

  // Handle hierarchical structure: count by category (section)
  mappedData.forEach((framework) => {
    framework.categories.forEach((category) => {
      category.controls.forEach((control) => {
        control.requirements.forEach((requirement) => {
          if (requirement.status === REQUIREMENT_STATUS.FAIL) {
            const type =
              typeof requirement.type === "string" ? requirement.type : "Fails";
            incrementFailedCount(failedSectionMap, category.name, type);
          }
        });
      });
    });
  });

  return buildTopFailedResult(failedSectionMap, TOP_FAILED_DATA_TYPE.SECTIONS);
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
  categories: Category[],
  categoryName: string,
): Category => {
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

export const findOrCreateControl = (
  controls: Control[],
  controlLabel: string,
): Control => {
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

export const calculateFrameworkCounters = (frameworks: Framework[]): void => {
  frameworks.forEach((framework) => {
    // Reset framework counters
    framework.pass = 0;
    framework.fail = 0;
    framework.manual = 0;

    // Handle flat structure (requirements directly in framework)
    const directRequirements = framework.requirements ?? [];
    if (directRequirements.length > 0) {
      directRequirements.forEach((requirement) => {
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
