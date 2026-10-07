# Keel home-region MemoryDB module

This module is a gated infrastructure candidate for the K4.7.3 pilot. It creates a single-shard Redis OSS MemoryDB cluster with one replica, the minimum topology candidate for the first Multi-AZ qualification; this is not a production capacity recommendation. It consumes an existing VPC, private subnets, a Keel workload security group, an existing workload IAM role, and an approved KMS key.

The module creates no resources by default. `enable_provisioning` must be set to `true`, and an `approval_reference`, `network_reviewed=true`, and `deployment_context_reviewed=true` must be supplied before any resource is planned. These inputs are guardrails, not substitutes for change review. The AWS account, region, node type, engine version, budget, operators, and exact ACL commands must be selected in the reviewed environment. Do not set the gate or apply this module based on this repository change alone.

## Security boundaries

- The MemoryDB security group accepts TCP 6379 only from the supplied Keel workload security group. Cluster node traffic is scoped to the MemoryDB security group itself. No CIDR or public ingress is created.
- The cluster uses the supplied subnets and an explicitly supplied customer-managed KMS key. Terraform verifies that subnets and the workload security group share a VPC and that the subnets span at least two Availability Zones. `network_reviewed` additionally requires a human to verify route tables and private-network ownership; the module cannot prove that those subnets are private.
- Transport TLS is enabled. MemoryDB always encrypts data at rest; `kms_key_arn` selects the customer-managed key for this cluster.
- The MemoryDB user uses IAM authentication. Terraform constructs the ACL key pattern from the limiter's home region and HMAC key ID, and takes only explicit command/subcommand names; command categories such as `+@all` cannot be supplied. Review the command set against Keel's exact Lua script, cluster discovery commands used by go-redis, and the chosen engine. A too-narrow ACL can cause fail-closed admission errors; do not widen it without reviewing command-level access.
- The supplied application role receives only `memorydb:Connect` on the created cluster and user ARNs. Infrastructure administration is outside this role policy.
- Minor engine upgrades are disabled so changes are reviewed. The module requests automatic snapshots and a named final snapshot on cluster deletion. Snapshot restore, encryption-key retention, and deletion plans must be rehearsed before a real deployment.

## Inputs that must be reviewed

| Input | Review requirement |
| --- | --- |
| `enable_provisioning` | Keep `false` in generic examples and CI. Set `true` only in the approved environment. |
| `approval_reference` | Point to the reviewed change and budget approval. |
| `network_reviewed` | Confirm private route tables, subnet ownership, AZ spread, and workload SG attachment. |
| `deployment_context_reviewed` | Confirm account, region, pricing/quota, service owner, on-call owner, and rollback owner are recorded. |
| `private_subnet_ids` | Existing subnets in at least two AZs in the same VPC as the workload SG. |
| `application_iam_role_name` | Dedicated Keel runtime identity; no broad infrastructure permissions. |
| `node_type`, `engine_version`, `kms_key_arn` | Resolve region availability, quota, price, engine support, and KMS policy before planning. |
| AWS provider region, `rate_limit_key_id`, `acl_command_names` | The provider region constructs the ACL key prefix and must match Keel runtime configuration; review every Redis command and key scope against the managed contract. |
| `snapshot_window`, `maintenance_window`, `final_snapshot_name` | Coordinate with service owner and restore/cleanup rehearsal. |

## Validation and plan workflow

From this directory, run `terraform init -backend=false`, `terraform validate`, and `terraform fmt -check`. The validation script verifies that the default-disabled example plans zero resource actions and that enabling it without approval/network/deployment-context inputs fails before VPC, subnet, or security-group data lookups. These checks require no AWS credentials or AWS API resource calls. A real plan must use the approved remote state backend, account, and region, be reviewed for resource replacement and cost, and be retained with its approval record. Never use local state for an applied environment.

Destroy is not the default cleanup path. A reviewed destroy plan must create the configured final snapshot, preserve its KMS key and required retention, and include a restore verification and explicit snapshot expiry. Do not delete the final snapshot or KMS key as part of the same cleanup step.

## Known qualification gaps

This module does not create the VPC, EKS cluster, workload role, KMS key, remote Terraform backend, dashboards, alert delivery, or service ownership. It does not prove Redis script or ACL compatibility, endpoint DNS/TLS behavior, IAM token refresh, failover, request overshoot, throughput, latency, cost, restore, or operator recovery. The opt-in Go contract test must run against an isolated managed test cluster before the module can be proposed for a production-small plan. No AWS resources were created by this change.

## References

- [MemoryDB IAM authentication and requirements](https://docs.aws.amazon.com/memorydb/latest/devguide/auth-iam.html)
- [MemoryDB ACL command and key access strings](https://docs.aws.amazon.com/memorydb/latest/devguide/clusters.acls.html)
- [MemoryDB private networking and endpoints](https://docs.aws.amazon.com/memorydb/latest/devguide/nodes-connecting.html)
- [MemoryDB consistency and failover semantics](https://docs.aws.amazon.com/memorydb/latest/devguide/consistency.html)
- [Terraform `aws_memorydb_cluster`](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/memorydb_cluster)
- [Terraform `aws_memorydb_user`](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/memorydb_user)
