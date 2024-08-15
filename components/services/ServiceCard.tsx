import { Card, CardBody, Chip } from "@nextui-org/react";

import { getAWSIcon, NotificationIcon, SuccessIcon } from "../icons";

interface CardServiceProps {
  fidingsFailed: number;
  serviceAlias: string;
}
export const ServiceCard: React.FC<CardServiceProps> = ({
  fidingsFailed,
  serviceAlias,
}) => {
  return (
    <Card fullWidth isPressable isHoverable shadow="sm">
      <CardBody className="flex flex-row items-center space-x-4 justify-between">
        <div className="flex space-x-4 items-center">
          {getAWSIcon(serviceAlias)}
          <div className="flex flex-col">
            <h4 className="font-bold text-md 3xl:text-lg leading-5">
              {serviceAlias}
            </h4>
            <small className="text-default-500">
              {fidingsFailed > 0
                ? `${fidingsFailed} Failed Findings`
                : "All findings passed"}
            </small>
          </div>
        </div>

        <Chip
          className="h-10"
          variant="flat"
          startContent={
            fidingsFailed > 0 ? (
              <NotificationIcon size={18} />
            ) : (
              <SuccessIcon size={18} />
            )
          }
          color={fidingsFailed > 0 ? "danger" : "success"}
          radius="full"
          size="md"
        >
          {fidingsFailed > 0 ? fidingsFailed : "All passed"}
        </Chip>
      </CardBody>
    </Card>
  );
};
