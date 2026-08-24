import { InfoIcon } from "lucide-react";
import { ReactNode } from "react";

import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import { CustomLink } from "@/components/shadcn/custom/custom-link";

const PROVIDER_GROUPS_DOCS_URL =
  "https://docs.prowler.com/user-guide/tutorials/prowler-app-rbac#provider-groups";

export const UnlimitedVisibilitySection = ({
  children,
}: {
  children: ReactNode;
}) => {
  return (
    <section className="space-y-2">
      <div className="text-muted-foreground flex items-start gap-2 text-sm">
        <InfoIcon
          aria-hidden="true"
          className="text-bg-data-info mt-0.5 h-4 w-4 shrink-0"
        />
        <div className="flex flex-col gap-1">
          <p>
            Checking the box below grants visibility into every provider:
            resources, findings, scans, and compliance results, regardless of
            the provider groups selected.
          </p>
          <p>
            Unlimited Visibility is also{" "}
            <strong>required to use the Jira integration</strong>.{" "}
            <CustomLink href={PROVIDER_GROUPS_DOCS_URL} size="sm">
              Learn more about Provider Groups
            </CustomLink>
          </p>
        </div>
      </div>
      <div>{children}</div>
    </section>
  );
};

export const UnlimitedVisibilityField = ({
  isSelected,
  onValueChange,
}: {
  isSelected: boolean;
  onValueChange: (checked: boolean) => void;
}) => {
  return (
    <UnlimitedVisibilitySection>
      <div className="flex items-center gap-2">
        <Checkbox
          id="unlimited_visibility"
          name="unlimited_visibility"
          checked={isSelected}
          onCheckedChange={(checked) => onValueChange(Boolean(checked))}
          size="sm"
        />
        <label
          htmlFor="unlimited_visibility"
          className="text-small font-medium peer-disabled:cursor-not-allowed peer-disabled:opacity-70"
        >
          Enable Unlimited Visibility for this role
        </label>
      </div>
    </UnlimitedVisibilitySection>
  );
};
