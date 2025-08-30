# Aegis — Security Baseline & Auto-Remediation

> **Status:** Work in progress

An AWS security foundation with compliance (**AWS Config**), centralized logging (**CloudTrail, S3**), security detection (**AWS GuardDuty**) and real-time auto-remediation (**EventBridge + Lambda + SNS**).

# Overview 
This project bootstraps your AWS cloud account with a security spine baked in, all using Terraform (IaC). The spine enforces baseline controls (AWS Config) for compliance, S3 for central logs, one KMS key for encryptions (cheaper, faster, easy to rotate), and 3 lambda remediation that utilizes modern architecture with CloudTrail, EventBridge, and SNS for real time detection, remediation, and alert. It solves common security concerns such as open ports, log tampering, and malicious activity like crypto mining. 

Because security is job zero, I wanted to implement what I have learned from my AWS Security Specialty certification. Something that proves (secure-by-default),  operations maturity, and results. From here, it bridges both my love for Cloud Compting and Cybersecurity. 

# Capabilities
- **Hardened access:** SSM role/profile for EC2 to prefer Session Manager over SSH.
- **Centralized logging:** One S3 “log archive” bucket (BPA on, versioning, SSE-KMS).
- **KMS encryption:** Single KMS key to keep costs/simple (you can split later per service).
- **Compliance (AWS Config):** Curated AWS managed rules for an opinionated baseline.
- **Real-time response:** 
  - CloudTrail tamper auto-remediation (StopLogging/DeleteTrail/UpdateTrail/PutEventSelectors).
  - SSH/RDP world-open guard for Security Groups.
- **Alerts:** Encrypted SNS topics (HIGH / MED) with clear, actionable emails.

> **Note:** Currently 2 remediation Lambdas are deployed. A third (crypto-mining) is planned.

# Prerequisites
- **Terraform**: [Install](https://developer.hashicorp.com/terraform/install)
- **Install/Update AWS CLI v2**: --> [Tutorial here](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
- **Quick setup (`aws configure`)**: --> [Tutorial here](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-quickstart.html)
- You'll need your own tfvars with proper variable inputs. ***I have excluded mine for best practice. Never commit tfvars to version control.*** Create a dev.tfvars or prod.tfvars under /envs/dev or /envs/prod. In this example, I have used dev.tfvars. 
- A sample tfvars.example file is included to help you structure your variable inputs. Make sure to name it either **dev.tfvars** or **prod.tfvars** --> [Sample here](examples/dev.tfvars.example)
- **Service-Linked Role for AWS Config**
  - Role name: `AWSServiceRoleForConfig`. Some accounts already have it; some don’t.
  - If missing, create it using this CLI command or directly from the **AWS console**:
    ```bash
    aws iam create-service-linked-role --aws-service-name config.amazonaws.com
    ```
    If you see “has been taken,” it already exists (safe to ignore).

## Getting started
**To start, clone the repo then follow the steps under.**
```bash
# Open your CLI terminal (Linux, Windows Powershell, etc.)

# Configure your AWS profile (or use SSO)
aws configure
# Provide Access Key ID, Secret Access Key, and default region

# Change to an environment folder
cd ./aegis-aws-security/terraform/envs/dev

# Initialize / format / validate
# Run these commands:
terraform init -upgrade
terraform fmt -recursive
terraform validate

# Plan & apply with your tfvars
terraform plan  -var-file="dev.tfvars"
terraform apply -var-file="dev.tfvars"

# When you want to nuke everything it:
terraform destroy -var-file="dev.tfvars"