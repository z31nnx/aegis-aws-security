# Aegis Runbook
This runbook defines the standard procedures for investigating and remediating security events detected and auto-remediated by Aegis. This uses the **NIST CSF 2.0 (Cybersecurity Framework)**. The NIST CSF Has 6 core functions: **Govern (new), Identify, Protect, Detect, Respond,** and **Recover**. 

## Resources
For detailed information,  see the links below.
- [NIST Cybersecurity Framework Resource Center](https://www.nist.gov/cyberframework)
- [NIST Cybersecurity Framework 2.0 (PDF)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1299.pdf)

## 1. Govern (new in CSF 2.0)
This is about direction, strategy, expectations, policies and how to make the security robust (secure-by-default). For Aegis, it enforces common security (encryption (KMS), logging (**CloudTrail**), automation (**Lambda**), etc. always on by default). The runbook ownership lies with the deploying engineer (you or the Cloud SecOps team).

## 2. Identify
Know what assets are in scope, current security risks, staying updated with attacks and are understood. For Aegis, know what must continue to be viable (**CloudTrail**), know whats critical, Central **S3** bucket should hold logs, **AWS Config** rules identify risky states, **Security Hub** + **CIS/AWS Foundational standards**. 

## 3. Protect
The guardrails to keep your infrastructure safe. Aegis includes **KMS** encryptions, **IAM roles** for least-privilege, **S3** BPA (block public access), default EBS encryptions, and **Lambda** automation for remediation. 

## 4. Detect
How you spot security threats. **GuardDuty** findings for threats (crypto mining, anomalous API calls, malware, etc. ). **AWS Config** compliance detections (exposed ports, no MFA, **CloudTrail** off). **Security Hub** for unified security findings with scores. **SNS** for notifications of security remediations. 

## 5. Respond
What happens when there's a threat. **Lambda** automatically does near real-time response to security risks (**CloudTrail** Tamper, **SSH/RDP** exposed ports, and **GuardDuty** crypto mining findings) and sends you an SNS email. 

**CloudTrail** Tamper -> **Lambda** recreates/re-enables and uses the baseline code to return it back to its original states and notifies you. 

**SSH/RDP** Exposed Ports -> **Lambda** revokes ingress rules `0.0.0.0/0` (IPv4) and `::0` (IPv6) then sends an SNS email. 

**GuardDuty** Crypto Mining -> **Lambda** isolates the EC2 instance, applies quarantine SG, creates an EBS snapshot for forensic analysis, stop the instance, revokes the IAM role, then sends an SNS email. 

| Event Type        | Trigger                                         | Automated Response                                                                 | Verification                                           | Escalation if Fails                         |
|-------------------|-------------------------------------------------|------------------------------------------------------------------------------------|--------------------------------------------------------|---------------------------------------------|
| **CloudTrail Tamper** | Trail stopped, deleted, or updated             | Lambda recreates/re-enables CloudTrail using baseline config in Terraform, sends HIGH SNS alert | CloudTrail console -> multi-region trail active          | Inspect DLQ -> reapply Terraform baseline     |
| **SSH/RDP Open**  | SG rule with `0.0.0.0/0` (IPv4) or `::/0` (IPv6) | Lambda revokes ingress rule, sends MED SNS alert                 | Security Group console -> deleted ingress rules         | Manually remove rule / delete SG            |
| **Crypto Mining** | GuardDuty finding `CryptoCurrency:EC2/Bitcoin*` | Lambda isolates EC2 with quarantine SG, EBS snapshot, stops instance, revokes IAM role, sends HIGH SNS alert | EC2 instance only has Quarantine SG; EBS snapshot exists | Stop instance, detach IAM role, insert quarantine SG, take snapshot or rerun DLQ   |

## 6. Recover 
Getting back to a steady state. Clean up any unused resources like **EBS** snapshots, deleting compromised **EC2** instances, document lessons learned, and rerun terraform apply to restore baseline.

- **Terraform Baseline:** Run `terraform apply -var-file="file.tfvars"` to restore any missing baseline resources.  
- **Credential Rotation:** Rotate IAM roles if compromise is suspected.  
- **Cleanup:** Remove unused EBS snapshots, delete/terminate compromised EC2 instances.  
- **Lessons Learned:** Document incident details and update Terraform modules or Lambda logic to cover any uncovered gaps.  
