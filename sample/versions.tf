# 検証用: 複数プロバイダのバージョン制約を定義
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.6.3"
    }
    null = {
      source  = "hashicorp/null"
      version = ">= 3.2.0, < 4.0.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.40"
    }
  }
}
