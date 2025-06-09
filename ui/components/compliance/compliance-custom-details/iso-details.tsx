import { Requirement } from "@/types/compliance";

export const ISOCustomDetails = ({
  requirement,
}: {
  requirement: Requirement;
}) => {
  return (
    <div className="mb-4">
      <div className="mb-2 text-sm text-gray-800 dark:text-gray-200">
        {requirement.description}
      </div>
      <div className="flex flex-col gap-2 text-sm">
        {requirement.objetive_name && (
          <div className="flex items-center gap-2">
            <span className="font-medium">Objective:</span>
            <span>{requirement.objetive_name}</span>
          </div>
        )}
      </div>
    </div>
  );
};
