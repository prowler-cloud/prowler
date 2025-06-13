import Link from "next/link";

import { cn } from "@/lib/utils";

export const ComplianceLink = ({
  href,
  children,
}: {
  href: string;
  children: React.ReactNode;
}) => {
  return (
    <Link
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="break-all text-sm text-blue-600 decoration-1 transition-colors hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300"
    >
      {children}
    </Link>
  );
};

export const ComplianceDetailContainer = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  return <div className="space-y-4">{children}</div>;
};

export const ComplianceDetailSection = ({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) => {
  return (
    <div>
      <h4 className="text-muted-foreground mb-2 text-sm font-medium">
        {title}
      </h4>
      {children}
    </div>
  );
};

export const ComplianceDetailText = ({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) => {
  return <p className={`text-sm leading-relaxed ${className}`}>{children}</p>;
};

export const ComplianceBadgeContainer = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  return <div className="flex flex-wrap items-center gap-3">{children}</div>;
};

type BadgeColor =
  | "red" // Risk/Level/Severity
  | "blue" // Assessment/Method
  | "orange" // Type/Category
  | "green" // Weight/Score (positive)
  | "purple" // Profile
  | "indigo" // IDs/References
  | "gray"; // Additional Info/Neutral

export const ComplianceBadge = ({
  label,
  value,
  color,
  conditional = false,
}: {
  label: string;
  value: string | number;
  color: BadgeColor;
  conditional?: boolean;
}) => {
  const actualColor = conditional && Number(value) === 0 ? "gray" : color;

  const colorClasses = {
    red: "bg-red-50 text-red-700 ring-red-600/10 dark:bg-red-400/10 dark:text-red-400 dark:ring-red-400/20",
    blue: "bg-blue-50 text-blue-700 ring-blue-600/10 dark:bg-blue-400/10 dark:text-blue-400 dark:ring-blue-400/20",
    orange:
      "bg-orange-50 text-orange-700 ring-orange-600/10 dark:bg-orange-400/10 dark:text-orange-400 dark:ring-orange-400/20",
    green:
      "bg-green-50 text-green-700 ring-green-600/10 dark:bg-green-400/10 dark:text-green-400 dark:ring-green-400/20",
    purple:
      "bg-purple-50 text-purple-700 ring-purple-600/10 dark:bg-purple-400/10 dark:text-purple-400 dark:ring-purple-400/20",
    indigo:
      "bg-indigo-50 text-indigo-700 ring-indigo-600/10 dark:bg-indigo-400/10 dark:text-indigo-400 dark:ring-indigo-400/20",
    gray: "bg-gray-50 text-gray-600 ring-gray-500/10 dark:bg-gray-400/10 dark:text-gray-400 dark:ring-gray-400/20",
  };

  return (
    <div className="flex items-center gap-2">
      <span className="text-muted-foreground text-sm font-medium">
        {label}:
      </span>
      <span
        className={cn(
          "inline-flex items-center rounded-md px-2 py-1 text-xs font-medium ring-1 ring-inset",
          colorClasses[actualColor],
        )}
      >
        {value}
      </span>
    </div>
  );
};

export const ComplianceBulletList = ({
  title,
  items,
}: {
  title: string;
  items: string[];
}) => {
  if (!items || items.length === 0) return null;

  return (
    <ComplianceDetailSection title={title}>
      <div className="space-y-2">
        {items.map((item: string, index: number) => (
          <div key={index} className="flex items-start gap-2">
            <span className="text-muted-foreground mt-1 text-xs">•</span>
            <ComplianceDetailText>{item}</ComplianceDetailText>
          </div>
        ))}
      </div>
    </ComplianceDetailSection>
  );
};

export const ComplianceChipContainer = ({
  title,
  items,
}: {
  title: string;
  items: string[];
}) => {
  if (!items || items.length === 0) return null;

  return (
    <ComplianceDetailSection title={title}>
      <div className="flex flex-wrap gap-2">
        {items.map((item: string, index: number) => (
          <span
            key={index}
            className="inline-flex items-center rounded-md bg-gray-50 px-2 py-1 text-xs font-medium text-gray-600 ring-1 ring-inset ring-gray-500/10 dark:bg-gray-400/10 dark:text-gray-400 dark:ring-gray-400/20"
          >
            {item}
          </span>
        ))}
      </div>
    </ComplianceDetailSection>
  );
};
