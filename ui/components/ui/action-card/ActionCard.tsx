"use client";

import { Icon } from "@iconify/react";
import type { CardProps } from "@nextui-org/react";
import { Card, CardBody } from "@nextui-org/react";
import React from "react";

import { cn } from "@/lib";

export type ActionCardProps = CardProps & {
  icon: string;
  title: string;
  color?: "success" | "secondary" | "warning" | "fail";
  description: string;
};

export const ActionCard = React.forwardRef<HTMLDivElement, ActionCardProps>(
  ({ color, title, icon, description, children, className, ...props }, ref) => {
    const colors = React.useMemo(() => {
      switch (color) {
        case "success":
          return {
            card: "border-system-success-medium",
            iconWrapper: "bg-system-success-lighter border-system-success",
            icon: "text-system-success",
          };
        case "secondary":
          return {
            card: "border-secondary-100",
            iconWrapper: "bg-secondary-50 border-secondary-100",
            icon: "text-secondary",
          };
        case "warning":
          return {
            card: "border-warning-500",
            iconWrapper: "bg-warning-50 border-warning-100",
            icon: "text-warning-600",
          };
        case "fail":
          return {
            card: "border-danger-300",
            iconWrapper: "bg-danger-50 border-danger-100",
            icon: "text-danger",
          };

        default:
          return {
            card: "border-default-200",
            iconWrapper: "bg-default-50 border-default-100",
            icon: "text-default-500",
          };
      }
    }, [color]);

    return (
      <Card
        ref={ref}
        isPressable
        className={cn("border-small", colors?.card, className)}
        shadow="sm"
        {...props}
      >
        <CardBody className="flex h-full flex-row items-center gap-2 p-2">
          <div
            className={cn(
              "item-center flex rounded-medium border p-1",
              colors?.iconWrapper,
            )}
          >
            <Icon className={colors?.icon} icon={icon} width={24} />
          </div>
          <div className="flex flex-col">
            <p className="text-md">{title}</p>
            <p className="text-sm text-default-400">
              {description || children}
            </p>
          </div>
        </CardBody>
      </Card>
    );
  },
);

ActionCard.displayName = "ActionCard";
