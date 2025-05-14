"use client";

import { useEffect, useState } from "react";

import { getFindings } from "@/actions/findings/findings";

interface ClientAccordionContentProps {
  requirement: any;
  scanId: string;
}

function getStatusEmoji(status: string) {
  if (status === "PASS") return "✅";
  if (status === "FAIL") return "❌";
  if (status === "MANUAL") return "🖐";
  return "";
}

function translateType(tipo: string) {
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
}

export function ClientAccordionContent({
  requirement,
  scanId,
}: ClientAccordionContentProps) {
  const [findings, setFindings] = useState<any>(null);
  const [isExpanded, setIsExpanded] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // When the component is mounted (which means it is expanded)
  useEffect(() => {
    async function loadFindings() {
      if (!isExpanded && requirement.checks && requirement.checks.length > 0) {
        setIsExpanded(true);
        setIsLoading(true);

        const checkIds = requirement.checks.map(
          (check: any) => check.checkName,
        );

        const findingsData = await getFindings({
          filters: {
            "filter[check_id__in]": checkIds.join(","),
            "filter[scan]": scanId,
          },
        });

        console.log("ATRIBUTES", findingsData.data[0].attributes);

        setFindings(findingsData);
        setIsLoading(false);
      }
    }

    loadFindings();
  }, [requirement, scanId, isExpanded]);

  // Reuse the renderTable logic but now with dynamically loaded findings
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

      {/* Sección de findings cargados dinámicamente */}
      {isLoading && (
        <div className="mt-4 p-2 text-gray-500">
          Cargando detalles adicionales...
        </div>
      )}

      {!isLoading && findings && findings.data && findings.data.length > 0 && (
        <div className="mt-4">
          <h3 className="mb-2 font-medium">Findings Details</h3>
          <table className="w-full min-w-full border text-left text-sm">
            <thead>
              <tr className="border-b bg-gray-50">
                <th className="p-2">ID</th>
                <th className="p-2">Resource</th>
                <th className="p-2">Region</th>
                <th className="p-2">Status</th>
              </tr>
            </thead>
            <tbody>
              {findings.data.map((finding: any) => (
                <tr key={finding.id} className="border-b">
                  <td className="p-2">{finding.id}</td>
                  <td className="p-2">
                    {finding.attributes?.resource_name || "N/A"}
                  </td>
                  <td className="p-2">{finding.attributes?.region || "N/A"}</td>
                  <td className="p-2">{finding.attributes?.status || "N/A"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
