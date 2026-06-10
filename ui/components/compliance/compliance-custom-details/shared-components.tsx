import { VariantProps } from "class-variance-authority";

import { Badge, badgeVariants } from "@/components/shadcn/badge/badge";

// Variants come straight from the canonical shadcn Badge so compliance panels
// share the same badge vocabulary (and tokens) as the rest of the app.
export type ComplianceBadgeVariant = NonNullable<
  VariantProps<typeof badgeVariants>["variant"]
>;

export const ComplianceDetailContainer = ({
  children,
}: {
  children: React.ReactNode;
}) => {
  return <div className="flex flex-col gap-4">{children}</div>;
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

export const ComplianceBadge = ({
  label,
  value,
  variant,
  conditional = false,
}: {
  label: string;
  value: string | number;
  variant: ComplianceBadgeVariant;
  conditional?: boolean;
}) => {
  // A "conditional" metric badge with a zero value drops to a neutral variant
  // so empty scores don't read as a meaningful (e.g. positive) result.
  const actualVariant: ComplianceBadgeVariant =
    conditional && Number(value) === 0 ? "secondary" : variant;

  return (
    <div className="flex items-center gap-2">
      <span className="text-muted-foreground text-sm font-medium">
        {label}:
      </span>
      <Badge variant={actualVariant}>{value}</Badge>
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
      <div className="flex flex-col gap-2">
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
          <Badge key={index} variant="tag">
            {item}
          </Badge>
        ))}
      </div>
    </ComplianceDetailSection>
  );
};
