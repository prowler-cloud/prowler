import { Icon } from "@iconify/react";
import Link from "next/link";

import { Button } from "@/components/shadcn/button/button";
import { Separator } from "@/components/shadcn/separator/separator";

interface NavigationHeaderProps {
  title: string;
  icon: string;
  href?: string;
}

export const NavigationHeader = ({
  title,
  icon,
  href,
}: NavigationHeaderProps) => {
  return (
    <>
      <header className="border-border-neutral-secondary flex items-center gap-3 border-b px-6 py-4">
        <Button
          className="border-border-neutral-secondary bg-transparent p-0"
          aria-label="Navigation button"
          variant="outline"
          size="icon"
          asChild
        >
          <Link href={href || ""}>
            <Icon icon={icon} className="text-text-neutral-secondary" />
          </Link>
        </Button>
        <Separator orientation="vertical" className="h-6" />
        <h1 className="text-text-neutral-secondary text-xl font-light">
          {title}
        </h1>
      </header>
    </>
  );
};
