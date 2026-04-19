from botocore.exceptions import ClientError
from datetime import datetime, timezone
import logging
import boto3
import json
import os

REGION = os.getenv("REGION", "us-east-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
ROLE_ARNS = json.loads(os.getenv("ROLE_ARNS", '[]'))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO)

TAG_STATUS_KEY = "Aegis:Status"
TAG_LASTFIX_KEY = "Aegis:LastFix"

sts = boto3.client("sts", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)
ec2 = boto3.client("ec2", region_name=REGION)

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
                    
                    for v4 in perm.get("IpRanges", []):
                        ipv4 = v4["CidrIp"]
                        
                    for v6 in perm.get("Ipv6Ranges", []):
                        ipv6 = v6["CidrIpv6"]
                        
                    open_to_world = ["0.0.0.0/0", "::/0"]
                    sensitive_ports = [22, 3389]
                    
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
            

def lambda_handler(event, context):
    logger.info("Lambda started!")
    logger.info(f"Event received: {json.dumps(event)}")
    logger.info("Starting audit...")
    
    exposed = scan_exposed_sg(ec2)
    remediate = remediate_exposed_sg(ec2, exposed)
    tagging = tag_sg(ec2, remediate)
    
    
    
    for role_arn in ROLE_ARNS:
        session = assume_role(role_arn=role_arn, session_name="AegisAutomation")
        account = session.client("sts").get_caller_identity()["Account"]
        logger.info(f"Scanning account: {account}")
    
        
lambda_handler(event=None, context=None)
        
        
                
                
                