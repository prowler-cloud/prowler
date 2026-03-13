import { Divider } from "@heroui/divider";

export const AuthDivider = () => {
  return (
    <div className="flex items-center gap-4 py-2">
      <Divider className="flex-1" />
      <p className="text-tiny text-default-500 shrink-0">OR</p>
      <Divider className="flex-1" />
    </div>
  );
};
