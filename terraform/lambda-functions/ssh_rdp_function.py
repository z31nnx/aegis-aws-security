from botocore.exceptions import ClientError
from datetime import datetime, timezone
import logging
import boto3
import json
import os

REGION = os.getenv("REGION", "us-east-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
TABLE_NAME = os.getenv("TABLE_NAME")
TARGET_ROLE_ARNS = json.loads(os.getenv("TARGET_ROLE_ARNS", "[]"))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO)

if not SNS_TOPIC_ARN:
    raise RuntimeError("Required: missing SNS_TOPIC_ARN env")

sts = boto3.client("sts", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

def log_client_error(e: ClientError, where: str) -> None:
    code = e.response["Error"].get("Code", "Unknown code")
    msg = e.response["Error"].get("Message", "No message")
    logger.exception(f"Error caught in {where}: {code} - {msg}")
    
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def assume_role(role_arn) -> boto3.Session: 
    try:
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AegisSecurity"
        )["Credentials"]
    
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=REGION
        )
        
    except ClientError as e:
        log_client_error(e, "assume_role")
        raise
    
def scan_exposed_sg(ec2) -> list[dict]:
    findings = []
    
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for p in paginator.paginate():
            for sg in p.get("SecurityGroups", []):
                group_id = sg["GroupId"]
                group_name = sg["GroupName"]
                
                for perm in sg.get("IpPermissions", []):
                    protocol = perm.get("IpProtocol", "All")
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")
                    
                    open_to_world = ["0.0.0.0/0", "::/0"]
                    sensitive_ports = [22, 3389]
                    
                    for v4 in perm.get("IpRanges", []):
                        ipv4 = v4["CidrIp"]
                        if ipv4 in open_to_world and protocol == "tcp":
                            if from_port in sensitive_ports and to_port == from_port:
                                findings.append({
                                    "GroupId": group_id,
                                    "GroupName": group_name,
                                    "Protocol": protocol,
                                    "FromPort": from_port,
                                    "ToPort": to_port,
                                    "Ipv4": ipv4,
                                    "Ipv6": None
                                })
                                
                    for v6 in perm.get("Ipv6Ranges", []):
                        ipv6 = v6["CidrIpv6"]
                        if ipv6 in open_to_world and protocol == "tcp":
                            if from_port in sensitive_ports and to_port == from_port:
                                findings.append({
                                    "GroupId": group_id,
                                    "GroupName": group_name,
                                    "Protocol": protocol,
                                    "FromPort": from_port,
                                    "ToPort": to_port,
                                    "Ipv6": ipv6,
                                    "Ipv4": None
                                })
                                
    except ClientError as e:
        log_client_error(e, "scan_exposed_sg")
        raise
    
    return findings

def remediate_exposed_sg(ec2, sgs) -> list[dict]: 
    findings = []
    
    for sg in sgs:
        try:
            group_id = sg["GroupId"]
            ipv4 = sg["Ipv4"]
            ipv6 = sg["Ipv6"]
            
            if ipv4:
                ec2.revoke_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=[
                        {
                            "IpProtocol": sg["Protocol"],
                            "FromPort": sg["FromPort"],
                            "ToPort": sg["ToPort"],
                            "IpRanges": [
                                {
                                    "CidrIp": ipv4
                                }
                            ]
                        }
                    ]
                )

            if ipv6:
                ec2.revoke_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=[
                        {
                            "IpProtocol": sg["Protocol"],
                            "FromPort": sg["FromPort"],
                            "ToPort": sg["ToPort"],
                            "Ipv6Ranges": [
                                {
                                    "CidrIpv6": ipv6
                                }
                            ]
                        }
                    ]
                )
                
            findings.append({
                "GroupId": group_id,
                "GroupName": sg["GroupName"],
                "Protocol": sg["Protocol"],
                "FromPort": sg["FromPort"],
                "ToPort": sg["ToPort"],
                "Ipv4": sg["Ipv4"],
                "Ipv6": sg["Ipv6"],
                "Action": "RevokeSecurityGroupIngress",
                "Status": "Success"
            })
            
        except ClientError as e:
            log_client_error(e, "remediate_exposed_sg")
            findings.append({
                "GroupId": sg.get("GroupId"),
                "GroupName": sg.get("GroupName"),
                "Protocol": sg.get("Protocol"),
                "FromPort": sg.get("FromPort"),
                "ToPort": sg.get("ToPort"),
                "Ipv4": sg.get("Ipv4"),
                "Ipv6": sg.get("Ipv6"),
                "Action": "RevokeSecurityGroupIngress",
                "Status": "Failed",
                "Error": e.response["Error"].get("Message", "Unknown remediation error")
            })

    return findings

def tags() -> list[dict]:
    return [
        {"Key": "Aegis:Status", "Value": "remediated"},
        {"Key": "Aegis:LastFix", "Value": now_utc_iso()},
        {"Key": "Aegis:Reason", "Value": "OpenToWorld"}
    ]

def tag_sg(ec2, sgs) -> bool:
    try:
        group_ids = []
        for sg in sgs:
            if sg.get("Status") == "Success":
                group_ids.append(sg["GroupId"])
        
        if not group_ids:
            return False
        
        ec2.create_tags(
            Resources=group_ids,
            Tags=tags()
        )
        
    except ClientError as e:
        log_client_error(e, "tag_sg")
        return False
    
    return True

def actor_meta(detail) -> dict:
    ui = detail.get("userIdentity", {}) or {}
    
    return {
        "Type": ui.get("type"),
        "Arn": ui.get("arn"),
        "AccountId": ui.get("accountId"),
        "User": ui.get("userName")
    }
    
def build_subject() -> str:
    return f"[Aegis/Medium] Security Group Exposure Alert"

def build_message(region, event_name, event_id, time, ip, actor, body) -> str:
    return f"""Security Group exposure findings detected.

Severity: Medium
Region: {region}
Event: {event_name}
EventID: {event_id}
Time (UTC): {time}
Source IP: {ip}

Actor: {json.dumps(actor, indent=2)}

Findings: {json.dumps(body, indent=2)}

Recommended Actions:
- Review the actor and source IP that triggered the event.
- Confirm the exposed security group rule was expected or unauthorized.
- Validate that remediation succeeded.
- Re-run the audit to confirm the exposure is closed.
"""

def publish_sns(arn, subject, message):
    try:
        sns.publish(
            TopicArn=arn,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        log_client_error(e, "publish_sns")
      
      
def lambda_handler(event, context):
    logger.info("Lambda Started!")
    logger.info(f"Event received: {json.dumps(event)}")
    logger.info("Starting audit...")
    
    event = event or {}
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
    event_id = detail.get("eventID", "Unknown")
    ip = detail.get("sourceIpAddress", "Unknown")
    time = now_utc_iso()
    actor = actor_meta(detail)
    
    ec2 = boto3.client("ec2", region_name=REGION)
    source_account = sts.get_caller_identity()["Account"]
    
    results = []

    exposed = scan_exposed_sg(ec2=ec2)
    if exposed:
        logger.info(f"Found exposed Security Groups in Source Account: {source_account}")
        logger.info(f"Remediating source account.")
        remediate = remediate_exposed_sg(ec2=ec2, sgs=exposed)
        tagging = tag_sg(ec2=ec2, sgs=remediate)
        logger.info(f"Source account remediation complete.")
            
        results.append({
            "Status": "NON-COMPLIANT",
            "Account": source_account,
            "UpdatedTags": tagging,
            "Findings": remediate
        })
        
    if TARGET_ROLE_ARNS:
        for role_arn in TARGET_ROLE_ARNS:
            try:
                logger.info(f"Multi account: Assuming target roles")
                session = assume_role(role_arn=role_arn)
                target_account = session.client("sts").get_caller_identity()["Account"]
                logger.info(f"Scanning account: {target_account}")
                target_ec2 = session.client("ec2", region_name=REGION)
                
                exposed = scan_exposed_sg(ec2=target_ec2)
                if exposed:
                    logger.info(f"Remediating target")
                    remediate = remediate_exposed_sg(ec2=target_ec2, sgs=exposed)
                    tagging = tag_sg(ec2=target_ec2, sgs=remediate)
                    results.append({
                        "Status": "NON-COMPLIANT",
                        "Account": target_account,
                        "UpdatedTags": tagging,
                        "Findings": remediate
                    })
                    
            except ClientError as e:
                log_client_error(e, f"target_account_processing:{role_arn}")
                results.append({
                    "Status": "ERROR",
                    "RoleArn": role_arn,
                    "Reason": "AssumeRole or account processing failed"
                })
                continue
    
    total_findings = 0
    for r in results:
        total_findings += len(r.get("Findings", []))
    
    body = {
        "Results": results,
        "TotalFindings": total_findings
    }
    
    if SNS_TOPIC_ARN:
        subject = build_subject()
        message = build_message(
            region=REGION,
            event_name=event_name,
            event_id=event_id,
            time=time,
            ip=ip,
            actor=actor,
            body=body
        )

        publish_sns(
            arn=SNS_TOPIC_ARN,
            subject=subject,
            message=message
        )    

    logger.info("Alert publish complete.")
    
    return {
        "statusCode": 200,
        "body": json.dumps(body)
    }