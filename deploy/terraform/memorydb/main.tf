data "aws_security_group" "application" {
  count = var.enable_provisioning ? 1 : 0
  id    = var.application_security_group_id
}

data "aws_subnet" "private" {
  for_each = var.enable_provisioning ? var.private_subnet_ids : toset([])
  id       = each.value
}

locals {
  limiter_acl_access_string = join(" ", concat(
    ["on", "~keel:rl:v1:${data.aws_region.current.region}:${var.rate_limit_key_id}:*"],
    [for command in sort(tolist(var.acl_command_names)) : "+${command}"]
  ))
}

data "aws_region" "current" {}

resource "aws_security_group" "memorydb" {
  count       = var.enable_provisioning ? 1 : 0
  name        = "${var.name}-memorydb"
  description = "Private Keel home-region MemoryDB cluster access"
  vpc_id      = data.aws_security_group.application[0].vpc_id

  tags = merge(var.tags, {
    Name      = "${var.name}-memorydb"
    Component = "rate-limit-authority"
  })

  lifecycle {
    precondition {
      condition     = alltrue([for subnet in data.aws_subnet.private : subnet.vpc_id == data.aws_security_group.application[0].vpc_id])
      error_message = "Every MemoryDB subnet must be in the same VPC as the Keel workload security group."
    }
    precondition {
      condition     = length(toset([for subnet in data.aws_subnet.private : subnet.availability_zone])) >= 2
      error_message = "MemoryDB subnets must cover at least two Availability Zones."
    }
    precondition {
      condition     = var.network_reviewed
      error_message = "Review subnet routes and private-network ownership before provisioning."
    }
    precondition {
      condition     = length(trimspace(var.approval_reference)) > 0
      error_message = "An approval_reference is required before provisioning."
    }
  }
}

resource "aws_vpc_security_group_ingress_rule" "application" {
  count                        = var.enable_provisioning ? 1 : 0
  security_group_id            = aws_security_group.memorydb[0].id
  referenced_security_group_id = data.aws_security_group.application[0].id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  description                  = "Keel home-region rate-limit client"
}

resource "aws_vpc_security_group_ingress_rule" "cluster_nodes" {
  count                        = var.enable_provisioning ? 1 : 0
  security_group_id            = aws_security_group.memorydb[0].id
  referenced_security_group_id = aws_security_group.memorydb[0].id
  ip_protocol                  = "-1"
  description                  = "MemoryDB node-to-node traffic within the cluster security group"
}

resource "aws_vpc_security_group_egress_rule" "cluster_nodes" {
  count                        = var.enable_provisioning ? 1 : 0
  security_group_id            = aws_security_group.memorydb[0].id
  referenced_security_group_id = aws_security_group.memorydb[0].id
  ip_protocol                  = "-1"
  description                  = "MemoryDB node-to-node traffic within the cluster security group"
}

resource "aws_memorydb_subnet_group" "this" {
  count       = var.enable_provisioning ? 1 : 0
  name        = "${var.name}-subnets"
  description = "Private subnets for Keel home-region MemoryDB"
  subnet_ids  = var.private_subnet_ids

  tags = merge(var.tags, { Name = "${var.name}-subnets" })
}

resource "aws_memorydb_user" "limiter" {
  count         = var.enable_provisioning ? 1 : 0
  user_name     = var.memorydb_user_name
  access_string = local.limiter_acl_access_string

  authentication_mode {
    type = "iam"
  }

  tags = merge(var.tags, { Name = var.memorydb_user_name })
}

resource "aws_memorydb_acl" "limiter" {
  count      = var.enable_provisioning ? 1 : 0
  name       = "${var.name}-limiter"
  user_names = [aws_memorydb_user.limiter[0].user_name]

  tags = merge(var.tags, { Name = "${var.name}-limiter" })
}

resource "aws_memorydb_cluster" "this" {
  count                      = var.enable_provisioning ? 1 : 0
  name                       = var.name
  description                = "Keel single-home-region Redis admission authority"
  engine                     = "redis"
  engine_version             = var.engine_version
  node_type                  = var.node_type
  num_shards                 = 1
  num_replicas_per_shard     = 1
  subnet_group_name          = aws_memorydb_subnet_group.this[0].name
  security_group_ids         = [aws_security_group.memorydb[0].id]
  acl_name                   = aws_memorydb_acl.limiter[0].name
  port                       = 6379
  tls_enabled                = true
  kms_key_arn                = var.kms_key_arn
  auto_minor_version_upgrade = false
  snapshot_retention_limit   = var.snapshot_retention_days
  snapshot_window            = var.snapshot_window
  maintenance_window         = var.maintenance_window
  final_snapshot_name        = var.final_snapshot_name
  tags = merge(var.tags, {
    Name      = var.name
    Component = "rate-limit-authority"
  })
}

resource "aws_iam_role_policy" "connect" {
  count = var.enable_provisioning ? 1 : 0
  name  = "${var.name}-memorydb-connect"
  role  = var.application_iam_role_name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ConnectToKeelRateLimitCluster"
      Effect   = "Allow"
      Action   = ["memorydb:Connect"]
      Resource = [aws_memorydb_cluster.this[0].arn, aws_memorydb_user.limiter[0].arn]
    }]
  })
}
