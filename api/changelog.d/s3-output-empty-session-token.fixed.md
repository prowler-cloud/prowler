Fix presigned report downloads failing with AccessDenied on S3-compatible object storage by omitting the empty AWS session token in `get_s3_client`
