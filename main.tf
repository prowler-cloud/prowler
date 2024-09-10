provider "aws" {
  region = "us-east-1"  # Cambia la región si es necesario
}

######################
# Configuración válida (PASS)
######################

# Crear un bucket S3 que será el origen de la distribución de CloudFront (cumple con el control)
resource "aws_s3_bucket" "pass_hugo_bucket" {
  bucket = "pass-hugo-cloudfront-origin"
  tags = {
    Name = "pass-hugo-cloudfront-origin-bucket"
  }
}

# Crear una política de bucket para permitir que CloudFront acceda a los objetos
resource "aws_s3_bucket_policy" "pass_hugo_bucket_policy" {
  bucket = aws_s3_bucket.pass_hugo_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          AWS = "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity ${aws_cloudfront_origin_access_identity.pass_hugo_oai.id}"
        },
        Action   = "s3:GetObject",
        Resource = "${aws_s3_bucket.pass_hugo_bucket.arn}/*"
      }
    ]
  })
}

# Crear la identidad de acceso de origen de CloudFront (OAI) para la configuración válida
resource "aws_cloudfront_origin_access_identity" "pass_hugo_oai" {
  comment = "Hugo's OAI for CloudFront pass distribution"
}

# Crear la distribución de CloudFront apuntando al bucket S3 existente (cumple)
resource "aws_cloudfront_distribution" "pass_hugo_distribution" {
  origin {
    domain_name = aws_s3_bucket.pass_hugo_bucket.bucket_regional_domain_name
    origin_id   = "pass-hugo-s3-origin"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.pass_hugo_oai.cloudfront_access_identity_path
    }
  }

  enabled             = true
  is_ipv6_enabled      = true
  comment              = "Pass: Hugo's CloudFront distribution with existing S3 bucket"

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "pass-hugo-s3-origin"

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "pass-hugo-cloudfront-distribution"
  }
}

######################
# Configuración no válida (FAIL)
######################

# Crear la identidad de acceso de origen de CloudFront (OAI) para la configuración no válida
resource "aws_cloudfront_origin_access_identity" "fail_hugo_oai" {
  comment = "Hugo's OAI for CloudFront fail distribution"
}

# Crear la distribución de CloudFront apuntando a un bucket S3 que no existe (no cumple)
resource "aws_cloudfront_distribution" "fail_hugo_distribution" {
  origin {
    domain_name = "fail-hugo-non-existent-bucket.s3.amazonaws.com"  # Origen no existe
    origin_id   = "fail-hugo-s3-origin"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.fail_hugo_oai.cloudfront_access_identity_path
    }
  }

  enabled             = true
  is_ipv6_enabled      = true
  comment              = "Fail: Hugo's CloudFront distribution with non-existent S3 bucket"

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "fail-hugo-s3-origin"

    viewer_protocol_policy = "redirect-to-https"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "fail-hugo-cloudfront-distribution"
  }
}
