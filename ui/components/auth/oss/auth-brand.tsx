import { ProwlerBrand } from "@/components/icons";
import { cn } from "@/lib/utils";

interface AuthBrandProps {
  className?: string;
}

export const AuthBrand = ({ className }: AuthBrandProps) => {
  return (
    <div className={cn("relative z-10 w-[200px]", className)}>
      <ProwlerBrand className="w-full" />
    </div>
  );
};
