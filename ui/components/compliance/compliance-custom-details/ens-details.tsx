import { translateType } from "@/lib/compliance/ens";
import { Requirement } from "@/types/compliance";

export const ENSCustomDetails = ({
  requirement,
}: {
  requirement: Requirement;
}) => {
  return (
    <div className="mb-4">
      <div className="mb-2 text-sm text-gray-600">
        {requirement.description}
      </div>
      <div className="flex flex-col gap-2 text-sm">
        <div className="flex items-center gap-2">
          <span className="font-medium">Type:</span>
          <span className="capitalize">
            {translateType(requirement.type as string)}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="font-medium">Level:</span>
          <span className="capitalize">{requirement.nivel}</span>
        </div>
        {requirement.dimensiones &&
          Array.isArray(requirement.dimensiones) &&
          requirement.dimensiones.length > 0 && (
            <div className="flex items-center gap-2">
              <span className="font-medium">Dimensions:</span>
              <div className="flex flex-wrap gap-1">
                {requirement.dimensiones.map(
                  (dimension: string, index: number) => (
                    <span
                      key={index}
                      className="rounded-full bg-gray-100 px-2 py-0.5 text-xs capitalize dark:bg-prowler-blue-400"
                    >
                      {dimension}
                    </span>
                  ),
                )}
              </div>
            </div>
          )}
      </div>
    </div>
  );
};
