provider "aws" {
  region = "us-east-1"
}

# Crear un bucket de S3 con el nombre "hugo"
resource "aws_s3_bucket" "hugo_bucket_oac" {
  bucket = "hugo-bucket-oac"
}

# Crear una Origin Access Control (OAC) para CloudFront
resource "aws_cloudfront_origin_access_control" "hugo_oac" {
  name = "hugo-oac"

  origin_access_control_origin_type = "s3"
  signing_behavior = "always"
  signing_protocol = "sigv4"
  description = "OAC for hugo CloudFront distribution"
}

# Crear una distribución de CloudFront que utilice el OAC
resource "aws_cloudfront_distribution" "hugo_distribution" {
  enabled             = true
  is_ipv6_enabled     = true
  comment             = "CloudFront distribution for hugo"
  default_root_object = "index.html"

  origin {
    domain_name = aws_s3_bucket.hugo_bucket_oac.bucket_regional_domain_name
    origin_id   = "hugo-s3-origin"

    origin_access_control_id = aws_cloudfront_origin_access_control.hugo_oac.id
  }

  default_cache_behavior {
    target_origin_id       = "hugo-s3-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

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

  price_class = "PriceClass_100"
}

# Crear una política de solicitud de origen para la distribución (opcional)
resource "aws_cloudfront_origin_request_policy" "hugo_request_policy" {
  name = "hugo-origin-request-policy"

  cookies_config {
    cookie_behavior = "none"
  }

  headers_config {
    header_behavior = "whitelist"
    headers {
      items = ["Origin"]
    }
  }

  query_strings_config {
    query_string_behavior = "none"
  }
}

# Crear una política de caché (opcional)
resource "aws_cloudfront_cache_policy" "hugo_cache_policy" {
  name = "hugo-cache-policy"

  default_ttl = 86400
  max_ttl     = 31536000
  min_ttl     = 0

  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"
    }

    headers_config {
      header_behavior = "none"
    }

    query_strings_config {
      query_string_behavior = "none"
    }
  }
}
