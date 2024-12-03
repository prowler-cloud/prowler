import React from "react";

import { ActionCard } from "@/components/ui";

const cardData = [
  {
    findings: 3,
    title: "Internet Exposed Resources",
  },
  {
    findings: 15,
    title: "Exposed Secrets",
  },
  {
    findings: 0,
    title: "IAM Policies Leading to Privilege Escalation",
  },
  {
    findings: 0,
    title: "EC2 with Metadata Service V1 (IMDSv1)",
  },
];

export const AttackSurface = () => {
  return (
    <div className="flex flex-col gap-2">
      {cardData.map((card, index) => (
        <ActionCard
          key={index}
          color={card.findings > 0 ? "fail" : "success"}
          icon={
            card.findings > 0
              ? "solar:danger-triangle-bold"
              : "heroicons:shield-check-solid"
          }
          title={card.title}
          description={
            card.findings > 0 ? "Review Required" : "No Issues Found"
          }
        />
      ))}
    </div>
  );
};
