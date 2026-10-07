output "cluster_arn" {
  description = "MemoryDB cluster ARN, or null while provisioning is disabled."
  value       = try(aws_memorydb_cluster.this[0].arn, null)
}

output "cluster_endpoint" {
  description = "MemoryDB cluster endpoint address, or null while provisioning is disabled."
  value       = try(aws_memorydb_cluster.this[0].cluster_endpoint[0].address, null)
}

output "cluster_port" {
  description = "MemoryDB cluster endpoint port, or null while provisioning is disabled."
  value       = try(aws_memorydb_cluster.this[0].cluster_endpoint[0].port, null)
}

output "memorydb_user_arn" {
  description = "IAM-authenticated MemoryDB ACL user ARN."
  value       = try(aws_memorydb_user.limiter[0].arn, null)
}

output "memorydb_security_group_id" {
  description = "MemoryDB-only security group ID."
  value       = try(aws_security_group.memorydb[0].id, null)
}
