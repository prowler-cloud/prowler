import { Separator } from "@/components/shadcn";

export const AuthDivider = () => {
  return (
    <div className="flex items-center gap-3">
      <Separator className="flex-1" />
      <p className="text-text-neutral-tertiary shrink-0 text-xs">or</p>
      <Separator className="flex-1" />
    </div>
  );
};
