from botocore.exceptions import ClientError
from datetime import datetime, timezone
import logging
import boto3
import json
import os

REGION = os.getenv("REGION", "us-east-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:718394780433:security-aegis-sns-medium")
ROLE_ARNS = json.loads(os.getenv("ROLE_ARNS", '[]'))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO)

if not SNS_TOPIC_ARN:
    raise RuntimeError("Required: missing SNS_TOPIC_ARNS")

TAG_STATUS_KEY = "Aegis:Status"
TAG_LASTFIX_KEY = "Aegis:LastFix"

sts = boto3.client("sts", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

def log_client_error(e: ClientError, where: str) -> None:
    code = e.response["Error"].get("Code", "Unknown code")
    msg = e.response["Error"].get("Message", "No message")
    logger.exception(f"Error caught in {where}: {code} - {msg}")

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def assume_role(role_arn: str, session_name: str) -> boto3.Session:
    try:
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name
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
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                group_id = sg["GroupId"]
                group_name = sg.get("GroupName", "unnamed")
                
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
        
    return findings

def remediate_exposed_sg(ec2, security_groups) -> list[dict]:
    findings = []
    
    try:
        for sg in security_groups:
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
                "Revoked": group_id,
                "GroupName": sg["GroupName"],
                "FromPort": sg["FromPort"],
                "ToPort": sg["ToPort"],
                "Ipv4": sg["Ipv4"],
                "Ipv6": sg["Ipv6"]
            })
            
    except ClientError as e:
        log_client_error(e, "remediate_exposed_sg")
        
    return findings

def tags():
    return [
        {"Key": TAG_STATUS_KEY, "Value": "remediated"},
        {"Key": TAG_LASTFIX_KEY, "Value": now_utc_iso()}
    ]

def tag_sg(ec2, security_groups) -> bool:
    try:
        group_ids = [sg["Revoked"] for sg in security_groups]
        ec2.create_tags(
            Resources=group_ids,
            Tags=tags()
        )
            
    except ClientError as e:
        log_client_error(e, "tag_sg")
        return False
    
    return True

def actor_meta(detail) -> dict:
    ui = detail.get("userIdentity")
    
    return {
        "Type": ui.get("type"),
        "Arn": ui.get("arn"),
        "AccountId": ui.get("accountId"),
        "User": ui.get("userName")
    }
    
def build_subject() -> str:
    return f"[Aegis/Medium] Security Groups Alert"

def build_message(findings) -> str:
    return f"""Security Groups findings found.

Severity: Medium
Region: {REGION}

Findings: {findings}

Recommended Actions:
- View the current findings listed above.
- Remediate findings ASAP.
- Validate wether security findings adhere with security compliance.
- Re-run the audit to match current compliance.
- Touch grass if needed.
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
    logger.info("Lambda started!")
    logger.info(f"Event received: {json.dumps(event)}")
    logger.info("Starting audit...")
    
    detail = event.get("detail", {})
    event_name = detail.get("eventName")
    ip = detail.get("sourceIpAddress")
    when = now_utc_iso()
    actor = actor_meta(detail)
    
    all_results =[]
    
    try:
        source_acc = sts.get_caller_identity()["Account"]
    except ClientError as e:
        log_client_error(e, "Failed to retrive source account")
    
    source_ec2 = boto3.client("ec2", region_name=REGION)         
    exposed = scan_exposed_sg(ec2=source_ec2)
    if exposed:
        logger.info(f"Found exposed Security Groups in Source Account: {source_acc}")
        logger.info(f"Remediating source account.")
        remediate = remediate_exposed_sg(ec2=source_ec2, security_groups=exposed)
        tagging = tag_sg(ec2=source_ec2, security_groups=remediate)
        logger.info(f"Source account remediation complete.")
        
        all_results.append({
            "Status": "NON-COMPLIANT",
            "Account": source_acc,
            "UpdatedTags": tagging,
            "Remediated": remediate
        })
    
    if ROLE_ARNS:
        for role_arn in ROLE_ARNS:
            session = assume_role(role_arn=role_arn, session_name="AegisAutomation")
            account = session.client("sts").get_caller_identity()["Account"]
            logger.info(f"Scanning account: {account}")
        
    body = {
        "TIME (UTC)": when,
        "EventName": event_name,
        "SourceIP": ip,
        "Actor": actor,
        "Results": all_results
    }
        
    subject = build_subject()
    message = build_message(findings=json.dumps(body, indent=2))
    
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
        
lambda_handler(event=None, context=None)
        
        
                
                
                