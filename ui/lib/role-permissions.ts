import { permissionFormFields } from "@/lib";

const hiddenOutsideCloudFields = [
  "manage_billing",
  "manage_alerts",
  "manage_lighthouse_ai_configuration",
  "manage_registry",
];

export const getVisiblePermissionFormFields = (
  isCloudEnvironment: boolean,
  isRealtimeEnabled = false,
) =>
  permissionFormFields.filter(
    (permission) =>
      permission.field !== "unlimited_visibility" &&
      (!hiddenOutsideCloudFields.includes(permission.field) ||
        isCloudEnvironment) &&
      // Realtime is Cloud-only and behind a PostHog flag, which never resolves on in OSS.
      (permission.field !== "manage_prowler_realtime" || isRealtimeEnabled),
  );

export const getUnlimitedVisibilityField = () =>
  permissionFormFields.find(({ field }) => field === "unlimited_visibility");
