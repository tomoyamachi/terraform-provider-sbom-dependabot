# 検証用ローカルモジュール: S3バケット
variable "name" {
  type = string
}

resource "aws_s3_bucket" "this" {
  bucket = "sbom-test-${var.name}"
}
