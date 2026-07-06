import { useEffect, useRef } from "react";
import type {
  FieldValues,
  Path,
  PathValue,
  UseFormReturn,
} from "react-hook-form";

import { permissionFormFields } from "@/lib";

type RolePermissionValues = {
  manage_providers?: boolean;
  unlimited_visibility?: boolean;
};

const hiddenOutsideCloudFields = ["manage_billing", "manage_alerts"];

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

export const getVisiblePermissionFormFields = (isCloudEnvironment: boolean) =>
  permissionFormFields.filter(
    (permission) =>
      permission.field !== "unlimited_visibility" &&
      (!hiddenOutsideCloudFields.includes(permission.field) ||
        isCloudEnvironment),
  );

export const getUnlimitedVisibilityField = () =>
  permissionFormFields.find(({ field }) => field === "unlimited_visibility");

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

  useEffect(() => {
    if (manageProviders && unlimitedVisibility === false) {
      autoEnabledUnlimitedVisibility.current = true;
      setBooleanFormValue(form, "unlimited_visibility" as Path<T>, true);
    }
  }, [form, manageProviders, unlimitedVisibility]);

  return {
    isUnlimitedVisibilityRequiredByManageProviders: !!manageProviders,
    setPermissionValue,
    setUnlimitedVisibility,
  };
};
