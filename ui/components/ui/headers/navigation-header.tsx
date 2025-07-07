import { Icon } from "@iconify/react";
import { Divider } from "@nextui-org/react";
import React from "react";

import { CustomLink } from "@/components/ui/custom/custom-link";

interface NavigationHeaderProps {
  title: string;
  icon: string;
  href?: string;
}

export const NavigationHeader: React.FC<NavigationHeaderProps> = ({
  title,
  icon,
  href,
}) => {
  return (
    <>
      <header className="flex items-center gap-3 border-b border-gray-200 px-6 py-4 dark:border-gray-800">
        <CustomLink
          path={href || ""}
          className="rounded-xl border-2 border-gray-200 bg-prowler-grey-medium bg-transparent p-3"
          ariaLabel="Navigation button"
          color="muted"
        >
          <Icon icon={icon} className="text-gray-600 dark:text-gray-400" />
        </CustomLink>
        <Divider orientation="vertical" className="h-6" />
        <h1 className="text-xl font-light text-default-700">{title}</h1>
      </header>
    </>
  );
};
