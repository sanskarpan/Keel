#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
terraform_bin="${TERRAFORM_BIN:-terraform}"
module_dir="${repo_root}/deploy/terraform/memorydb"
example_dir="${module_dir}/examples/disabled"
plan_file="$(mktemp)"
plan_json="$(mktemp)"
gate_output="$(mktemp)"
trap 'rm -f "${plan_file}" "${plan_json}" "${gate_output}"' EXIT

"${terraform_bin}" fmt -check -recursive "${module_dir}"
"${terraform_bin}" -chdir="${module_dir}" init -backend=false -input=false -lockfile=readonly
"${terraform_bin}" -chdir="${module_dir}" validate
"${terraform_bin}" -chdir="${example_dir}" init -backend=false -input=false -lockfile=readonly
"${terraform_bin}" -chdir="${example_dir}" validate
AWS_ACCESS_KEY_ID=disabled-plan \
AWS_SECRET_ACCESS_KEY=disabled-plan \
AWS_REGION=us-east-1 \
AWS_EC2_METADATA_DISABLED=true \
  "${terraform_bin}" -chdir="${example_dir}" plan -input=false -lock=false -out="${plan_file}"
"${terraform_bin}" -chdir="${example_dir}" show -json "${plan_file}" >"${plan_json}"
python3 - "${plan_json}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as plan_file:
    plan = json.load(plan_file)
changes = plan.get("resource_changes", [])
planned = [item for item in changes if item.get("change", {}).get("actions") != ["no-op"]]
if planned:
    raise SystemExit(f"disabled MemoryDB plan contains resource actions: {planned!r}")
print("Disabled MemoryDB module plan contains zero resource actions.")
PY

if AWS_ACCESS_KEY_ID=disabled-plan \
  AWS_SECRET_ACCESS_KEY=disabled-plan \
  AWS_REGION=us-east-1 \
  AWS_EC2_METADATA_DISABLED=true \
  "${terraform_bin}" -chdir="${example_dir}" plan -input=false -lock=false \
    -var="enable_provisioning=true" >"${gate_output}" 2>&1; then
  cat "${gate_output}"
  echo "Enabling MemoryDB without review inputs unexpectedly produced a plan." >&2
  exit 1
fi

if ! grep -Fq "Enabling provisioning requires an approval reference" "${gate_output}"; then
  cat "${gate_output}"
  echo "Enabled plan failed for a reason other than the expected review gate." >&2
  exit 1
fi
echo "Enabling provisioning without review inputs is rejected before VPC, subnet, or security-group lookup."
