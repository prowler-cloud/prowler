import { Card, CardBody, CardHeader, Divider } from "@nextui-org/react";
import { CardProps as NextUICardProps } from "@nextui-org/react";
import React from "react";
interface CustomBoxProps {
  children: React.ReactNode;
  preTitle?: string;
  subTitle?: string;
  title?: string;
}

export const CustomBox = ({
  children,
  preTitle,
  subTitle,
  title,
  ...props
}: CustomBoxProps & NextUICardProps & React.HTMLAttributes<HTMLDivElement>) => {
  return (
    <Card fullWidth {...props}>
      {(preTitle || subTitle || title) && (
        <>
          <CardHeader className="flex-col items-start px-3 py-2">
            {preTitle && (
              <p className="text-tiny font-bold uppercase">{preTitle}</p>
            )}
            {subTitle && <small className="text-default-500">{subTitle}</small>}
            {title && <h4 className="text-large font-bold">{title}</h4>}
          </CardHeader>
          <Divider />
        </>
      )}
      <CardBody className="px-3 pb-4 pt-3">{children}</CardBody>
    </Card>
  );
};
