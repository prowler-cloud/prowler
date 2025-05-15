"use client";

import { translateType } from "@/lib/ens-compliance";

type FailedSectionItem = {
  name: string;
  total: number;
  types: {
    [key: string]: number;
  };
};

interface FailedSectionsListProps {
  sections: FailedSectionItem[];
}

export default function FailedSectionsList({
  sections,
}: FailedSectionsListProps) {
  const getTypeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case "requisito":
        return "text-red-600 dark:text-red-400 font-medium";
      case "recomendacion":
        return "text-yellow-600 dark:text-yellow-400 font-medium";
      case "refuerzo":
        return "text-blue-600 dark:text-blue-400 font-medium";
      case "medida":
        return "text-purple-600 dark:text-purple-400 font-medium";
      default:
        return "text-gray-600 dark:text-gray-400 font-medium";
    }
  };

  return (
    <div className="flex h-[400px] flex-col items-center justify-between rounded-lg border-2 border-gray-200 p-4 dark:border-gray-700">
      <h3 className="mb-4 whitespace-nowrap text-lg font-medium">
        Failed Sections (Top 5)
      </h3>

      <div className="flex">
        <div className="space-y-1">
          {sections.map((section, index) => (
            <div
              key={index}
              className="border-b border-gray-200 pb-3 last:border-b-0 dark:border-gray-700"
            >
              <div className="flex items-center justify-between gap-2">
                <h4 className="text-sm font-medium">
                  {section.name.charAt(0).toUpperCase() + section.name.slice(1)}
                </h4>
                <span className="whitespace-nowrap rounded-full bg-red-100 px-2 py-1 text-xs font-medium text-red-800 dark:bg-red-900 dark:text-red-200">
                  Fails: {section.total}
                </span>
              </div>

              <div className="mt-2 flex flex-wrap gap-2">
                {Object.entries(section.types)
                  .sort((a, b) => b[1] - a[1])
                  .map(([type, count], i) => (
                    <p key={i} className={`text-xs ${getTypeColor(type)}`}>
                      {translateType(type)}: {count}
                    </p>
                  ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
