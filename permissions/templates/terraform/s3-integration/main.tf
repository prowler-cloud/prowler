# S3 Integration Policy
###################################
resource "aws_iam_role_policy" "prowler_s3_integration" {
  name = "ProwlerS3Integration"
  role = var.prowler_role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:DeleteObject"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::${var.s3_integration_bucket_name}/*test-prowler-connection.txt"
        ]
        Condition = {
          StringEquals = {
            "s3:ResourceAccount" = var.s3_integration_bucket_account
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::${var.s3_integration_bucket_name}/*"
        ]
        Condition = {
          StringEquals = {
            "s3:ResourceAccount" = var.s3_integration_bucket_account
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          "arn:${data.aws_partition.current.partition}:s3:::${var.s3_integration_bucket_name}"
        ]
        Condition = {
          StringEquals = {
            "s3:ResourceAccount" = var.s3_integration_bucket_account
          }
        }
      }
    ]
  })
}
