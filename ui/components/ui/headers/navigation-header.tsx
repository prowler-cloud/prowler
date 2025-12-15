import { Divider } from "@heroui/divider";
import { Icon } from "@iconify/react";
import Link from "next/link";

import { Button } from "@/components/shadcn";

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
      <header className="flex items-center gap-3 border-b border-gray-200 px-6 py-4 dark:border-gray-800">
        <Button
          className="border-gray-200 bg-transparent p-0"
          aria-label="Navigation button"
          variant="outline"
          size="icon"
          asChild
        >
          <Link href={href || ""}>
            <Icon icon={icon} className="text-gray-600 dark:text-gray-400" />
          </Link>
        </Button>
        <Divider orientation="vertical" className="h-6" />
        <h1 className="text-default-700 text-xl font-light">{title}</h1>
      </header>
    </>
  );
};
