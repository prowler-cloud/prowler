import { Icon } from "@iconify/react";
import { Divider } from "@nextui-org/react";
import Link from "next/link";
import React from "react";

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
        <Link
          className="mr-3 flex h-[2.625rem] w-[2.625rem] items-center justify-center rounded-lg border border-solid border-gray-200 hover:bg-gray-200 dark:hover:bg-gray-700"
          href={href || ""}
        >
          <Icon
            icon={icon}
            className="h-5 w-5 text-gray-600 dark:text-gray-400"
          />
        </Link>
        <Divider orientation="vertical" className="h-6" />
        <h1 className="text-xl font-light text-default-700">{title}</h1>
      </header>
    </>
  );
};
