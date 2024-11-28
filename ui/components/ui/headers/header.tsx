import { Icon } from "@iconify/react";
import { Divider } from "@nextui-org/react";
import React from "react";

interface HeaderProps {
  title: string;
  icon: string;
}

export const Header: React.FC<HeaderProps> = ({ title, icon }) => {
  return (
    <>
      <header className="flex items-center gap-3 py-4">
        <Icon className="text-default-500" height={40} icon={icon} width={40} />
        <h1 className="text-2xl font-light text-default-700">{title}</h1>
      </header>
      <Divider className="mb-4" />
    </>
  );
};
