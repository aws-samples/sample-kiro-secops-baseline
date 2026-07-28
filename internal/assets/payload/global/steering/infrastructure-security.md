---
inclusion: fileMatch
fileMatchPattern:
  - "**/*.tf"
  - "**/*.tfvars"
  - "**/Dockerfile"
  - "**/docker-compose*.yml"
  - "**/k8s/**/*.yaml"
  - "**/*.cf.yaml"
  - "**/template.yaml"
---

# Security rules for Infrastructure as Code (IaC)

Applied automatically when editing Terraform, CloudFormation, Kubernetes, and Dockerfiles.
For the detailed IaC review, trigger the `kiro-secops-review` skill.

## Principles (AWS Well-Architected Security Pillar)
- **Least privilege:** minimal IAM roles/policies; no broad `Action: "*"` / `Resource: "*"`.
- **No static credentials:** use roles/OIDC/instance profiles; never hardcoded keys.
- **Crypto by default:** encryption at rest (KMS) and in transit (TLS) enabled.
- **Traceability:** logging/auditing enabled (CloudTrail, VPC Flow Logs).

## Principles (AWS Foundational Security Best Practices — Security Hub CSPM)
FSBP is a *detective* standard evaluated on live accounts — treat these rules as its
*preventive*, shift-left mirror in IaC.
- **Identify:** know every resource; no unknown or publicly exposed assets; security contact set.
- **Protect:** encryption at rest/in transit by default; least-privilege IAM; hardened network & compute.
- **Detect:** CloudTrail, Config, GuardDuty, and VPC Flow Logs enabled and tamper-protected.
- **Respond & recover:** deletion protection, backups, and SCPs that block disabling controls.

## Concrete rules
- Buckets/storage: **block public access**; SSE-KMS; require TLS in the bucket policy;
  versioning where applicable.
- IAM: no full `"*"` admin; no wildcard service actions in customer-managed policies; attach
  policies to roles/groups, not IAM users.
- Encryption at rest by default: EBS default encryption; RDS/Aurora clusters encrypted.
- Network: security groups without `0.0.0.0/0` on administrative ports (22/3389); VPC default
  security group denies all traffic; private subnets for workloads; no unnecessary public IPs;
  RDS not publicly accessible.
- Compute: require IMDSv2; Lambda function policies must prohibit public access.
- Logging: CloudTrail enabled multi-region with log file validation; VPC Flow Logs in all VPCs.
- Secrets: dynamic reference to Secrets Manager/SSM; never a literal value in `.tf`/manifests;
  never passed as container environment variables.
- Containers: minimal base image pinned by digest; do **not** run as root
  (`runAsNonRoot`) / not `privileged`; read-only filesystem when possible; drop capabilities;
  ECR image scanning on push.
- Kubernetes: define `securityContext`, `resources` (limits/requests), `NetworkPolicy`;
  no `hostPath`/`hostNetwork` without justification.

## Policy-as-code (validate before deploy)
- Run `checkov -d .` and `trivy config .` locally and in CI (both ship FSBP-aligned rule packs).
- For AWS CloudFormation, consider `cfn-guard` as a preventive gate + CloudFormation Hooks.
- Organization SCPs must deny disabling CloudTrail/GuardDuty/Config/Security Hub.
