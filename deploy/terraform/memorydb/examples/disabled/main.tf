terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.57.1"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
  skip_requesting_account_id  = true
}

variable "enable_provisioning" {
  description = "Used by the validation script to exercise the explicit provisioning gate."
  type        = bool
  default     = false
}

module "memorydb" {
  source = "../.."

  name                          = "keel-local-plan"
  private_subnet_ids            = ["subnet-00000001", "subnet-00000002"]
  application_security_group_id = "sg-00000001"
  application_iam_role_name     = "unused-while-disabled"
  rate_limit_key_id             = "home-v1"
  acl_command_names             = ["cluster|slots", "eval", "evalsha", "hmget", "hset", "pexpire", "ping", "time"]
  node_type                     = "db.t4g.small"
  engine_version                = "7.1"
  kms_key_arn                   = "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000"
  final_snapshot_name           = "keel-local-plan-final"
  snapshot_window               = "03:00-04:00"
  maintenance_window            = "sun:05:00-sun:06:00"
  enable_provisioning           = var.enable_provisioning
  tags = {
    Owner              = "local-validation"
    Environment        = "test"
    CostCenter         = "not-billed"
    DataClassification = "synthetic"
  }
}
