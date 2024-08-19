import React from "react";

import ActionCard from "../ui/action-card/ActionCard";

const cardData = [
  {
    findings: 3,
    icon: "solar:danger-triangle-bold",
    title: "Internet Exposed Resources",
  },
  {
    findings: 15,
    icon: "solar:danger-triangle-bold",
    title: "Exposed Secrets",
  },
  {
    findings: 0,
    icon: "heroicons:shield-check-solid",
    title: "IAM Policies Leading to Privilege Escalation",
  },
  {
    findings: 0,
    icon: "heroicons:shield-check-solid",
    title: "EC2 with Metadata Service V1 (IMDSv1)",
  },
];

export const AttackSurface = () => {
  return (
    <div className="flex flex-col gap-3">
      {cardData.map((card, index) => (
        <ActionCard
          key={index}
          color={card.findings > 0 ? "fail" : "success"}
          icon={card.findings > 0 ? "solar:danger-triangle-bold" : card.icon}
          title={card.title}
          description={
            card.findings > 0 ? "Review Required" : "No Issues Found"
          }
        />
      ))}
    </div>
  );
};
