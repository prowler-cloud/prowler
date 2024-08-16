import { Card, CardBody, CardHeader, Divider } from "@nextui-org/react";
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
}: CustomBoxProps) => {
  return (
    <Card fullWidth>
      {(preTitle || subTitle || title) && (
        <>
          <CardHeader className="pt-4 pb-3 px-3 flex-col items-start">
            {preTitle && (
              <p className="text-tiny uppercase font-bold">{preTitle}</p>
            )}
            {subTitle && <small className="text-default-500">{subTitle}</small>}
            {title && <h4 className="font-bold text-large">{title}</h4>}
          </CardHeader>
          <Divider />
        </>
      )}
      <CardBody className="px-3 pt-3 pb-4">{children}</CardBody>
    </Card>
  );
};
