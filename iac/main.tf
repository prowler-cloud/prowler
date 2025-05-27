resource "aws_s3_bucket" "bad_example" {
  bucket = "my-unsafe-bucket"
  acl    = "public-read"
}
