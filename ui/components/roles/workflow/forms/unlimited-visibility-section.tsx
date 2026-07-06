import { Checkbox } from "@heroui/checkbox";
import { Eye } from "lucide-react";
import { ReactNode } from "react";

export const UnlimitedVisibilitySection = ({
  children,
}: {
  children: ReactNode;
}) => {
  return (
    <section className="rounded-lg border border-orange-300 bg-orange-50 p-4 dark:border-orange-800 dark:bg-orange-950/40">
      <div className="flex flex-col gap-4">
        <div className="flex items-start gap-3">
          <Eye className="mt-1 size-5 shrink-0 text-orange-700 dark:text-orange-300" />
          <div className="flex flex-col gap-2">
            <h2 className="text-lg font-semibold text-orange-950 dark:text-orange-100">
              Unlimited Visibility
            </h2>
            <p className="text-small text-orange-900 dark:text-orange-100">
              This is a tenant-wide visibility setting. It grants visibility
              into every provider, account, resource, finding, scan, and
              compliance result, regardless of the groups selected below.
            </p>
          </div>
        </div>

        <div className="text-small rounded-md border border-orange-200 bg-white/70 p-3 text-orange-950 dark:border-orange-800 dark:bg-orange-950/60 dark:text-orange-100">
          <p>
            <strong>What it does not grant:</strong> Unlimited Visibility does
            not grant admin actions such as managing users, providers, scans,
            integrations, billing, or alerts. Those actions still require their
            own admin permissions.
          </p>
          <p className="mt-2">
            <strong>When to enable it:</strong> Enable it only for roles that
            need tenant-wide security visibility, such as security leadership,
            audit, or global operations roles. Do not enable it for teams that
            should remain limited to specific groups or accounts.
          </p>
          <p className="mt-2">
            <strong>Manage Providers dependency:</strong> Manage Providers
            enables Unlimited Visibility in this form because provider
            administration needs tenant-wide provider-group context. Selecting
            Manage Providers, or Grant all admin permissions, enables this
            visibility setting automatically.
          </p>
        </div>

        <div className="pt-1">{children}</div>
      </div>
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
      {isDisabled && (
        <p className="text-small mt-2 text-orange-900 dark:text-orange-100">
          Manage Providers is selected, so Unlimited Visibility stays enabled in
          this form. If Manage Providers enabled it automatically, clearing
          Manage Providers also clears that automatic selection. If Unlimited
          Visibility was already enabled, clearing Manage Providers only lets
          you edit it separately.
        </p>
      )}
    </UnlimitedVisibilitySection>
  );
};
