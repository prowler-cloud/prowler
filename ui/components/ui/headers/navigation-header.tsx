import { Icon } from "@iconify/react";
import { Divider } from "@nextui-org/react";
import React from "react";

import { CustomButton } from "@/components/ui/custom/custom-button";

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
        <CustomButton
          asLink={href || ""}
          className="border-gray-200 bg-transparent p-0"
          ariaLabel="Navigation button"
          variant="bordered"
          isIconOnly
          radius="lg"
        >
          <Icon icon={icon} className="text-gray-600 dark:text-gray-400" />
        </CustomButton>
        <Divider orientation="vertical" className="h-6" />
        <h1 className="text-xl font-light text-default-700">{title}</h1>
      </header>
    </>
  );
};
