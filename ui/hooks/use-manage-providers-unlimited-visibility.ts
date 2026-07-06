import { useRef } from "react";
import type {
  FieldValues,
  Path,
  PathValue,
  UseFormReturn,
} from "react-hook-form";

type RolePermissionValues = {
  manage_providers?: boolean;
  unlimited_visibility?: boolean;
};

const setBooleanFormValue = <T extends FieldValues>(
  form: Pick<UseFormReturn<T>, "setValue">,
  field: Path<T>,
  value: boolean,
) => {
  form.setValue(field, value as PathValue<T, Path<T>>, {
    shouldValidate: true,
    shouldDirty: true,
    shouldTouch: true,
  });
};

export const useManageProvidersUnlimitedVisibility = <
  T extends FieldValues & RolePermissionValues,
>(
  form: Pick<UseFormReturn<T>, "setValue" | "watch">,
) => {
  const autoEnabledUnlimitedVisibility = useRef(false);

  const manageProviders = form.watch("manage_providers" as Path<T>);
  const unlimitedVisibility = form.watch("unlimited_visibility" as Path<T>);

  const setUnlimitedVisibility = (checked: boolean) => {
    if (manageProviders && !checked) {
      autoEnabledUnlimitedVisibility.current = true;
      setBooleanFormValue(form, "unlimited_visibility" as Path<T>, true);
      return;
    }

    autoEnabledUnlimitedVisibility.current = false;
    setBooleanFormValue(form, "unlimited_visibility" as Path<T>, checked);
  };

  const setPermissionValue = (field: string, checked: boolean) => {
    setBooleanFormValue(form, field as Path<T>, checked);

    if (field !== "manage_providers") {
      return;
    }

    if (checked && unlimitedVisibility === false) {
      autoEnabledUnlimitedVisibility.current = true;
      setBooleanFormValue(form, "unlimited_visibility" as Path<T>, true);
    }

    if (!checked && autoEnabledUnlimitedVisibility.current) {
      autoEnabledUnlimitedVisibility.current = false;
      setBooleanFormValue(form, "unlimited_visibility" as Path<T>, false);
    }
  };

  return {
    isUnlimitedVisibilityRequiredByManageProviders:
      !!manageProviders && !!unlimitedVisibility,
    setPermissionValue,
    setUnlimitedVisibility,
  };
};
