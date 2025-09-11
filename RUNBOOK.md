# Aegis Runbook
This is a lightweight runbook that defines the standard procedures for investigating and remediating security events detected and auto-remediated by Aegis. This uses the **NIST CSF 2.0 (Cybersecurity Framework)**. The NIST CSF Has 6 core functions: **Govern (new), Identify, Protect, Detect, Respond,** and **Recover**. 

## Resources
For detailed information,  see the links below.
- [NIST Cybersecurity Framework Resource Center](https://www.nist.gov/cyberframework)
- [NIST Cybersecurity Framework 2.0 (PDF)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.1299.pdf)

## Contents
- [1. Govern](#1-govern-new-in-csf-20)  
- [2. Identify](#2-identify)  
- [3. Protect](#3-protect)  
- [4. Detect](#4-detect)  
- [5. Respond](#5-respond)  
  - [CloudTrail Tamper](#cloudtrail-tamper)  
  - [SSH/RDP Open Ports](#sshrdp-open-ports)  
  - [Crypto Mining](#crypto-mining)  
- [6. Recover](#6-recover)   

## 1. Govern (new in CSF 2.0)
Defines strategy, policies, and secure-by-default expectations.  
- Always-on security: **KMS encryption**, **CloudTrail logging**, **Lambda automation**.  
- Ownership: Deploying engineer or Cloud SecOps team.  

## 2. Identify
Know what assets are in scope, current security risks, staying updated with attacks and are understood.
- **CloudTrail** must remain viable.  
- Central **S3** bucket for logs.  
- **AWS Config** rules to catch risky states.  
- **GuardDuty** To find malicious activities. 
- **Security Hub** + **CIS/AWS standards** for baselines. 

## 3. Protect
The guardrails to keep your infrastructure safe. 
- **KMS encryption** everywhere.  
- **IAM least-privilege roles**.  
- **S3 Block Public Access (BPA)**.  
- **Default EBS encryption**.  
- **Lambda automation** to enforce security policies.  

## 4. Detect
How you spot security threats. 
- **GuardDuty**: Crypto-mining, anomalous API calls, malware.  
- **AWS Config**: Compliance drift (exposed ports, no MFA, CloudTrail off).  
- **Security Hub**: Unified view with security scores.  
- **SNS**: Security notifications.  

## 5. Respond
What happens when there's a threat. 
### CloudTrail Tamper
- **Trigger:** CloudTrail stopped, deleted, or updated.  
- **Automated Response:** Lambda recreates/enables CloudTrail baseline, sends HIGH alert (SNS).  
- **Verification:** Check CloudTrail console -> multi-region trail active.  
- **Escalation:** Inspect DLQ -> reapply Terraform baseline.  

---

### SSH/RDP Open Ports
- **Trigger:** Security Group rule with `0.0.0.0/0` (IPv4) or `::/0` (IPv6).  
- **Automated Response:** Lambda revokes ingress rule, sends MED alert (SNS).  
- **Verification:** Security Group console -> rule removed.  
- **Escalation:** Manually delete SG or reapply Terraform baseline.  

---

### Crypto Mining
- **Trigger:** GuardDuty finding `CryptoCurrency:EC2/Bitcoin*`.  
- **Automated Response:**  
  - Lambda quarantines EC2 with isolated SG.  
  - Creates EBS snapshot for forensic analysis.  
  - Stops instance, revokes IAM role.  
  - Sends HIGH alert (SNS).  

- **Manual Forensic Procedure:**  
  1. Create isolated VPC (no IGW, no peering).  
  2. Launch forensic EC2 in quarantine VPC.  
  3. Attach snapshot volume (read-only).  
  4. Analyze evidence: `/var/log/`, SSH keys, new users, etc.  
  5. Preserve -> tag snapshot & document IDs/timeline.  
  6. Rebuild ->  clean/hardened patched AMI 

## 6. Recover 
Getting back to a steady state.

- **Terraform Baseline:** Run `terraform apply -var-file="file.tfvars"` to restore any missing baseline resources.  
- **Credential Rotation:** Rotate IAM roles if compromise is suspected.  
- **Cleanup:** Remove unused EBS snapshots, delete/terminate compromised EC2 instances.  
- **GuardDuty**: Confirm findings = 0 active.  
- **Config**: Confirm Config compliance score ≥ 95%. 
- **CloudTrail**: Confirm CloudTrail multi-region trail is ENABLED.   
- **Lessons Learned:** Document incident details and update Terraform modules or Lambda logic to cover any uncovered gaps.  
