import { Requirement } from "@/types/compliance";

export const ThreatCustomDetails = ({
  requirement,
}: {
  requirement: Requirement;
}) => {
  return (
    <div className="mb-4">
      {requirement.attributeDescription && (
        <div className="mb-3 text-sm">
          <span className="font-medium"> Description:</span>
          <p className="mt-1 text-gray-600 dark:text-gray-200">
            <div className="text-sm text-gray-600 dark:text-gray-200">
              {requirement.description}
            </div>
            {requirement.attributeDescription}
          </p>
        </div>
      )}

      {requirement.additionalInformation && (
        <div className="mb-3 text-sm">
          <span className="font-medium">Additional Information:</span>
          <p className="mt-1 text-gray-600 dark:text-gray-200">
            {requirement.additionalInformation}
          </p>
        </div>
      )}

      <div className="flex flex-col gap-2 text-sm">
        <div className="flex gap-2">
          {typeof requirement.levelOfRisk === "number" && (
            <div className="flex items-center gap-2">
              <span className="font-medium">Level of Risk:</span>
              <span className="rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-800 dark:bg-red-400/20 dark:text-red-400">
                {requirement.levelOfRisk}
              </span>
            </div>
          )}

          <span className="text-gray-600">-</span>

          {typeof requirement.weight === "number" && (
            <div className="flex items-center gap-2">
              <span className="font-medium">Weight:</span>
              <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-800 dark:bg-blue-400/20 dark:text-blue-400">
                {requirement.weight}
              </span>
            </div>
          )}

          <span className="text-gray-600">-</span>

          {typeof requirement.score === "number" && (
            <div className="flex items-center gap-2">
              <span className="font-medium">Score:</span>
              <span
                className={`rounded-full px-2 py-0.5 text-xs font-medium ${
                  requirement.score > 0
                    ? "bg-green-100 text-green-800 dark:bg-green-400/20 dark:text-green-400"
                    : "bg-gray-100 text-gray-800 dark:bg-gray-400/20 dark:text-gray-400"
                }`}
              >
                {requirement.score}
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
