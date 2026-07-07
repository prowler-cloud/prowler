import { Checkbox } from "@heroui/checkbox";
import { InfoIcon } from "lucide-react";
import { ReactNode } from "react";

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
        <p>
          This is a tenant-wide visibility setting. It grants visibility into
          every provider, account, resource, finding, scan, and compliance
          result, regardless of the groups selected below. It is also{" "}
          <strong>required to use the Jira integration</strong>.
        </p>
      </div>
      <div>{children}</div>
    </section>
  );
};

export const UnlimitedVisibilityField = ({
  isSelected,
  isDisabled,
  onValueChange,
}: {
  isSelected: boolean;
  isDisabled: boolean;
  onValueChange: (checked: boolean) => void;
}) => {
  return (
    <UnlimitedVisibilitySection>
      <Checkbox
        name="unlimited_visibility"
        isSelected={isSelected}
        isDisabled={isDisabled}
        onValueChange={onValueChange}
        classNames={{
          label: "text-small font-medium",
          wrapper: "checkbox-update",
        }}
        color="default"
      >
        Enable Unlimited Visibility for this role
      </Checkbox>
    </UnlimitedVisibilitySection>
  );
};
