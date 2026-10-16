# 検証用: プロバイダとモジュールを利用するリソース定義
provider "aws" {
  region                      = "ap-northeast-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_region_validation      = true
}

resource "random_pet" "name" {
  length = 2
}

resource "null_resource" "example" {}

# ローカルモジュール
module "local_bucket" {
  source = "./modules/bucket"
  name   = random_pet.name.id
}

# Terraform Registry のモジュール（バージョン固定）
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.16.0"

  name = "sbom-test"
  cidr = "10.0.0.0/16"
}
