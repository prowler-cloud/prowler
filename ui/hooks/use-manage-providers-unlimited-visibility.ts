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
  const setUnlimitedVisibility = (checked: boolean) => {
    setBooleanFormValue(form, "unlimited_visibility" as Path<T>, checked);
  };

  const setPermissionValue = (field: string, checked: boolean) => {
    setBooleanFormValue(form, field as Path<T>, checked);
  };

  return {
    setPermissionValue,
    setUnlimitedVisibility,
  };
};
