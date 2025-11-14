"use client";

import { getAWSIcon } from "@/components/icons/services/IconServices";

import { WatchlistCard, WatchlistItem } from "./watchlist-card";

const MOCK_SERVICE_ITEMS: WatchlistItem[] = [
  {
    key: "amazon-s3-1",
    icon: getAWSIcon("Amazon S3"),
    label: "Amazon S3",
    value: "5",
  },
  {
    key: "amazon-ec2",
    icon: getAWSIcon("Amazon EC2"),
    label: "Amazon EC2",
    value: "8",
  },
  {
    key: "amazon-rds",
    icon: getAWSIcon("Amazon RDS"),
    label: "Amazon RDS",
    value: "12",
  },
  {
    key: "aws-iam",
    icon: getAWSIcon("AWS IAM"),
    label: "AWS IAM",
    value: "15",
  },
  {
    key: "aws-lambda",
    icon: getAWSIcon("AWS Lambda"),
    label: "AWS Lambda",
    value: "22",
  },
  {
    key: "amazon-vpc",
    icon: getAWSIcon("Amazon VPC"),
    label: "Amazon VPC",
    value: "28",
  },
  {
    key: "amazon-cloudwatch",
    icon: getAWSIcon("AWS CloudWatch"),
    label: "AWS CloudWatch",
    value: "78",
  },
];

export const ServiceWatchlist = () => {
  return (
    <WatchlistCard
      title="Service Watchlist"
      items={MOCK_SERVICE_ITEMS}
      ctaLabel="Services Dashboard"
      ctaHref="/services"
      emptyState={{
        message: "This space is looking empty.",
        description: "to add services to your watchlist.",
        linkText: "Services Dashboard",
      }}
    />
  );
};
