import React from "react";

interface ComplianceInfoProps {
  name?: string;
  framework?: string;
  version?: string;
}

export const ComplianceInfo = ({ name, framework, version }: ComplianceInfoProps) => {
  return (
    <div className="space-y-4">
      {name && (
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{name}</h1>
      )}

      <div className="flex flex-wrap gap-2">
        {framework && (
          <span className="rounded-full bg-blue-100 px-3 py-1 text-sm font-medium text-blue-800 dark:bg-blue-900 dark:text-blue-200">
            {framework}
          </span>
        )}

        {version && (
          <span className="rounded-full bg-green-100 px-3 py-1 text-sm font-medium text-green-800 dark:bg-green-900 dark:text-green-200">
            {version}
          </span>
        )}
      </div>
    </div>
  );
};
