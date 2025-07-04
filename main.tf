provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "hugo_firehose_buckets" {
  count  = 15
  bucket = "hugo-firehose-bucket-${count.index}"
  force_destroy = true
}

resource "aws_iam_role" "hugo_firehose_role" {
  name = "hugo_firehose_delivery_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Principal = {
        Service = "firehose.amazonaws.com"
      }
      Effect = "Allow"
      Sid    = ""
    }]
  })
}

resource "aws_iam_role_policy" "hugo_firehose_policy" {
  name = "hugo_firehose_policy"
  role = aws_iam_role.hugo_firehose_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectAcl",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = [
          for b in aws_s3_bucket.hugo_firehose_buckets :
          "${b.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "hugo_streams" {
  count       = 15
  name        = "hugo-firehose-stream-${count.index}"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.hugo_firehose_role.arn
    bucket_arn = aws_s3_bucket.hugo_firehose_buckets[count.index].arn

    buffering_interval  = 300
    buffering_size      = 5
    compression_format  = "UNCOMPRESSED"
  }
}
