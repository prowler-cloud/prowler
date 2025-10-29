import { Card, CardBody } from "@heroui/card";
import { Chip } from "@heroui/chip";

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
      <CardBody className="flex flex-row items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          {getAWSIcon(serviceAlias)}
          <div className="flex flex-col">
            <h4 className="text-md leading-5 font-bold">{serviceAlias}</h4>
            <small className="text-default-500">
              {fidingsFailed > 0
                ? `${fidingsFailed} Failed Findings`
                : "No failed findings"}
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
          {fidingsFailed > 0 ? fidingsFailed : ""}
        </Chip>
      </CardBody>
    </Card>
  );
};
