terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5"
    }
  }
}

variable "aws_region" {
  description = "AWS region where the demo resources will be deployed."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix used to name all demo resources."
  type        = string
  default     = "prowler-firehose-false-positive"
}

variable "deploy_msk_demo" {
  description = "Set to true to provision the MSK-backed Firehose stream demo (long-lived and incurs cost)."
  type        = bool
  default     = false
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {}

resource "random_pet" "suffix" {
  length = 2
}

locals {
  bucket_name        = "${var.name_prefix}-${random_pet.suffix.id}"
  msk_vpc_cidr_block = "10.42.0.0/16"
  msk_subnet_azs     = var.deploy_msk_demo ? tolist(slice(data.aws_availability_zones.available.names, 0, 2)) : []
  msk_subnet_map     = { for index, az in local.msk_subnet_azs : az => index }
}

resource "aws_kms_key" "kinesis" {
  description             = "Customer managed key for Kinesis stream encryption."
  deletion_window_in_days = 7

  tags = {
    Name = "${var.name_prefix}-kinesis-kms"
  }
}

resource "aws_kms_alias" "kinesis" {
  name          = "alias/${var.name_prefix}-kinesis"
  target_key_id = aws_kms_key.kinesis.key_id
}

resource "aws_s3_bucket" "firehose" {
  bucket        = local.bucket_name
  force_destroy = true

  tags = {
    Name = "${var.name_prefix}-bucket"
  }
}

resource "aws_s3_bucket_versioning" "firehose" {
  bucket = aws_s3_bucket.firehose.id

  versioning_configuration {
    status = "Suspended"
  }
}

resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/${var.name_prefix}"
  retention_in_days = 7
}

resource "aws_iam_role" "firehose" {
  name = "${var.name_prefix}-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect    = "Allow",
        Principal = { Service = "firehose.amazonaws.com" },
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

data "aws_iam_policy_document" "firehose" {
  statement {
    sid       = "AllowS3Delivery"
    actions   = ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"]
    resources = [aws_s3_bucket.firehose.arn, "${aws_s3_bucket.firehose.arn}/*"]
  }

  statement {
    sid     = "AllowCloudWatchLogging"
    actions = ["logs:CreateLogDelivery", "logs:DeleteLogDelivery", "logs:GetLogDelivery", "logs:ListLogDeliveries", "logs:PutLogEvents", "logs:CreateLogStream", "logs:CreateLogGroup"]
    resources = [
      aws_cloudwatch_log_group.firehose.arn,
      "${aws_cloudwatch_log_group.firehose.arn}:*"
    ]
  }

  statement {
    sid       = "AllowKinesisSourceRead"
    actions   = ["kinesis:DescribeStream", "kinesis:GetShardIterator", "kinesis:GetRecords", "kinesis:ListShards"]
    resources = [aws_kinesis_stream.encrypted_source.arn]
  }

  statement {
    sid       = "AllowFirehoseUseKMS"
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey", "kms:ReEncrypt*"]
    resources = [aws_kms_key.kinesis.arn]
  }

  statement {
    sid     = "AllowMSKAccess"
    actions = [
      "kafka:DescribeCluster",
      "kafka:DescribeClusterV2",
      "kafka:GetBootstrapBrokers",
      "kafka-cluster:Connect",
      "kafka-cluster:DescribeCluster",
      "kafka-cluster:DescribeTopic",
      "kafka-cluster:ReadData",
      "kafka-cluster:DescribeGroup"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role_policy" "firehose" {
  name   = "${var.name_prefix}-policy"
  role   = aws_iam_role.firehose.id
  policy = data.aws_iam_policy_document.firehose.json
}

resource "aws_kinesis_stream" "encrypted_source" {
  name                 = "${var.name_prefix}-encrypted-source"
  shard_count          = 1
  retention_period     = 24
  encryption_type      = "KMS"
  kms_key_id           = aws_kms_key.kinesis.arn
  stream_mode_details {
    stream_mode = "PROVISIONED"
  }

  tags = {
    Name = "${var.name_prefix}-encrypted-source"
  }
}

resource "aws_kinesis_firehose_delivery_stream" "kinesis_source_without_sse" {
  name        = "${var.name_prefix}-from-kinesis"
  destination = "extended_s3"

  kinesis_source_configuration {
    kinesis_stream_arn = aws_kinesis_stream.encrypted_source.arn
    role_arn           = aws_iam_role.firehose.arn
  }

  extended_s3_configuration {
    role_arn           = aws_iam_role.firehose.arn
    bucket_arn         = aws_s3_bucket.firehose.arn
    buffering_interval = 300
    buffering_size     = 5
    compression_format = "UNCOMPRESSED"
    prefix             = "kinesis-source/"
  }
}

resource "aws_kinesis_firehose_delivery_stream" "direct_put_with_sse" {
  name        = "${var.name_prefix}-direct-put"
  destination = "extended_s3"

  server_side_encryption {
    enabled = true
    key_type = "CUSTOMER_MANAGED_CMK"
    key_arn  = aws_kms_key.kinesis.arn
  }

  extended_s3_configuration {
    role_arn           = aws_iam_role.firehose.arn
    bucket_arn         = aws_s3_bucket.firehose.arn
    buffering_interval = 300
    buffering_size     = 5
    compression_format = "UNCOMPRESSED"
    prefix             = "direct-put/"
  }
}

resource "aws_vpc" "msk" {
  count = var.deploy_msk_demo ? 1 : 0

  cidr_block           = local.msk_vpc_cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-msk-vpc"
  }
}

resource "aws_internet_gateway" "msk" {
  count = var.deploy_msk_demo ? 1 : 0

  vpc_id = aws_vpc.msk[0].id

  tags = {
    Name = "${var.name_prefix}-msk-igw"
  }
}

resource "aws_route_table" "msk" {
  count = var.deploy_msk_demo ? 1 : 0

  vpc_id = aws_vpc.msk[0].id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.msk[0].id
  }

  tags = {
    Name = "${var.name_prefix}-msk-rt"
  }
}

resource "aws_subnet" "msk" {
  for_each = local.msk_subnet_map

  vpc_id                  = aws_vpc.msk[0].id
  availability_zone       = each.key
  cidr_block              = cidrsubnet(local.msk_vpc_cidr_block, 4, each.value)
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-msk-subnet-${each.value}"
  }
}

resource "aws_route_table_association" "msk" {
  for_each = local.msk_subnet_map

  subnet_id      = aws_subnet.msk[each.key].id
  route_table_id = aws_route_table.msk[0].id
}

resource "aws_security_group" "msk" {
  count  = var.deploy_msk_demo ? 1 : 0
  vpc_id = aws_vpc.msk[0].id

  name        = "${var.name_prefix}-msk-sg"
  description = "Allow intra-VPC communication for MSK serverless demo."

  ingress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = [local.msk_vpc_cidr_block]
  }

  egress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-msk-sg"
  }
}

resource "aws_msk_serverless_cluster" "msk" {
  count = var.deploy_msk_demo ? 1 : 0

  cluster_name = "${var.name_prefix}-msk"

  client_authentication {
    sasl {
      iam {
        enabled = true
      }
    }
  }

  vpc_config {
    subnet_ids         = [for az in local.msk_subnet_azs : aws_subnet.msk[az].id]
    security_group_ids = [aws_security_group.msk[0].id]
  }

  tags = {
    Name = "${var.name_prefix}-msk"
  }
}

resource "aws_msk_cluster_policy" "msk_firehose_access" {
  count = var.deploy_msk_demo ? 1 : 0

  cluster_arn = aws_msk_serverless_cluster.msk[0].arn

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid      = "AllowFirehoseToConnect",
        Effect   = "Allow",
        Principal = {
          AWS = aws_iam_role.firehose.arn
        },
        Action = [
          "kafka-cluster:Connect",
          "kafka-cluster:DescribeCluster",
          "kafka-cluster:DescribeTopic",
          "kafka-cluster:DescribeGroup",
          "kafka-cluster:AlterGroup",
          "kafka:GetBootstrapBrokers",
          "kafka:DescribeCluster",
          "kafka:DescribeClusterV2"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "msk_source_without_sse" {
  count       = var.deploy_msk_demo ? 1 : 0
  name        = "${var.name_prefix}-from-msk"
  destination = "extended_s3"

  msk_source_configuration {
    msk_cluster_arn = aws_msk_serverless_cluster.msk[0].arn
    topic_name      = "firehose-demo-topic"

    authentication_configuration {
      connectivity = "PRIVATE"
      role_arn     = aws_iam_role.firehose.arn
    }
  }

  extended_s3_configuration {
    role_arn           = aws_iam_role.firehose.arn
    bucket_arn         = aws_s3_bucket.firehose.arn
    buffering_interval = 300
    buffering_size     = 5
    compression_format = "UNCOMPRESSED"
    prefix             = "msk-source/"
  }

  depends_on = [aws_msk_cluster_policy.msk_firehose_access]
}

output "kinesis_source_delivery_stream_name" {
  value       = aws_kinesis_firehose_delivery_stream.kinesis_source_without_sse.name
  description = "Firehose delivery stream without SSE that pulls from an encrypted Kinesis source."
}

output "direct_put_delivery_stream_name" {
  value       = aws_kinesis_firehose_delivery_stream.direct_put_with_sse.name
  description = "DirectPut Firehose delivery stream with server-side encryption enabled."
}

output "msk_source_delivery_stream_name" {
  value       = var.deploy_msk_demo ? aws_kinesis_firehose_delivery_stream.msk_source_without_sse[0].name : null
  description = "Firehose delivery stream without SSE that pulls from the MSK source (requires deploy_msk_demo=true and a pre-created Kafka topic)."
}
