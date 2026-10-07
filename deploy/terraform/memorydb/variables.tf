variable "enable_provisioning" {
  description = "Creates resources only when explicitly enabled after reviewing the plan, account, budget, region, and cleanup procedure."
  type        = bool
  default     = false

  validation {
    condition     = !var.enable_provisioning || (length(trimspace(var.approval_reference)) > 0 && var.network_reviewed && var.deployment_context_reviewed)
    error_message = "Enabling provisioning requires an approval reference, private-network review, and deployment-context review."
  }
}

variable "approval_reference" {
  description = "Change, issue, or approval record for the reviewed deployment. Required when provisioning is enabled."
  type        = string
  default     = ""
}

variable "network_reviewed" {
  description = "Confirms that the supplied subnets are private, span approved AZs, and use the intended VPC route tables."
  type        = bool
  default     = false
}

variable "deployment_context_reviewed" {
  description = "Confirms AWS account, region, engine/node availability, budget, service owner, on-call owner, and rollback owner are recorded."
  type        = bool
  default     = false
}

variable "name" {
  description = "Lowercase MemoryDB cluster name, limited to leave room for subnet and ACL suffixes."
  type        = string

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,30}[a-z0-9])?$", var.name))
    error_message = "name must be 1-32 lowercase letters, numbers, or hyphens and start with a letter, leaving room for resource suffixes."
  }
}

variable "private_subnet_ids" {
  description = "At least two existing private subnet IDs in separate Availability Zones in one VPC."
  type        = set(string)

  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "At least two private subnets are required for the Multi-AZ pilot topology."
  }
}

variable "application_security_group_id" {
  description = "Existing Keel workload security group allowed to connect to MemoryDB."
  type        = string
}

variable "application_iam_role_name" {
  description = "Existing workload IAM role that receives memorydb:Connect for this cluster and user only."
  type        = string
}

variable "memorydb_user_name" {
  description = "IAM-authenticated MemoryDB ACL username."
  type        = string
  default     = "keel-limiter"

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,38}[a-z0-9])?$", var.memorydb_user_name))
    error_message = "memorydb_user_name must be 1-40 lowercase letters, numbers, or hyphens and start with a letter."
  }
}

variable "rate_limit_key_id" {
  description = "Keel limiter HMAC key ID. ACL key access is restricted to this region and key prefix."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$", var.rate_limit_key_id)) && length(var.rate_limit_key_id) <= 64
    error_message = "rate_limit_key_id must match Keel's bounded key identifier format."
  }
}

variable "acl_command_names" {
  description = "Explicit Redis commands, including required cluster discovery subcommands, reviewed against the exact Keel client and MemoryDB engine. Do not pass command categories."
  type        = set(string)

  validation {
    condition = length(var.acl_command_names) > 0 && alltrue([
      for command in var.acl_command_names : can(regex("^[a-z0-9|_-]+$", command))
    ])
    error_message = "acl_command_names must contain explicit lowercase Redis command names and subcommands."
  }
}

variable "node_type" {
  description = "MemoryDB node type selected from the region-specific capacity and cost review. No default is provided."
  type        = string
}

variable "engine_version" {
  description = "Redis OSS engine version, pinned after checking IAM authentication support in the selected region."
  type        = string

  validation {
    condition     = can(regex("^[7-9]\\.[0-9]+(\\.[0-9]+)?$", var.engine_version))
    error_message = "engine_version must select Redis OSS 7.0 or newer to support IAM authentication."
  }
}

variable "kms_key_arn" {
  description = "Approved customer-managed KMS key ARN for encryption at rest."
  type        = string
}

variable "final_snapshot_name" {
  description = "Unique snapshot name required when Terraform deletes the cluster."
  type        = string

  validation {
    condition     = can(regex("^[a-z]([a-z0-9-]{0,38}[a-z0-9])?$", var.final_snapshot_name))
    error_message = "final_snapshot_name must be 1-40 lowercase letters, numbers, or hyphens and start with a letter."
  }
}

variable "snapshot_retention_days" {
  description = "Automatic snapshot retention, between 1 and 35 days."
  type        = number
  default     = 7

  validation {
    condition     = var.snapshot_retention_days >= 1 && var.snapshot_retention_days <= 35
    error_message = "snapshot_retention_days must be from 1 through 35."
  }
}

variable "snapshot_window" {
  description = "UTC daily snapshot window in MemoryDB format, for example 03:00-04:00."
  type        = string
}

variable "maintenance_window" {
  description = "Weekly maintenance window in MemoryDB format, for example sun:05:00-sun:06:00."
  type        = string
}

variable "tags" {
  description = "Organization-required ownership, environment, cost-center, and data-classification tags."
  type        = map(string)

  validation {
    condition = alltrue([
      for key in ["Owner", "Environment", "CostCenter", "DataClassification"] :
      contains(keys(var.tags), key) && length(trimspace(lookup(var.tags, key, ""))) > 0
    ])
    error_message = "tags must include non-empty Owner, Environment, CostCenter, and DataClassification values."
  }
}
