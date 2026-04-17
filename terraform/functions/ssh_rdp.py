from botocore.exceptions import ClientError
from datetime import datetime, timezone
import json, logging, boto3, os 

REGION = os.getenv("REGION", "us-east-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

sns = boto3.client("sns", region_name=REGION)
ec2 = boto3.client("ec2", region_name=REGION)

TAG_STATUS_KEY = "Aegis:Status"
TAG_LASTFIX_KEY = "Aegis:LastFix"

if not SNS_TOPIC_ARN:
    raise RuntimeError(f"Required: missing SNS_TOPIC_ARN.")

def log_client_error(e: ClientError, where: str) -> None:
    code = e.response["Error"].get("Code", "Unkown code")
    msg = e.response["Error"].get("Message", "No message")
    logger.exception(f"Error caught in {where}: {code} - {msg}")
    
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def scan_exposed_sg() -> list[dict]:
    findings = []
    
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                group_id = sg["GroupId"]
                group_name = sg["GroupName"]
                
                for perm in sg.get("IpPermissions", []):
                    protocol = perm.get("IpProtocol", "All")
                    fp = perm.get("FromPort")
                    tp = perm.get("ToPort")
                    
                    open_to_world = ["0.0.0.0/0", "::/0"]
                    exposed_ports = [22, 3389]
                    
                    for ip in perm.get("IpRanges", []):
                        ipv4 = ip.get("CidrIp")
                        if ipv4 in open_to_world and protocol == "tcp":
                            if fp in exposed_ports and tp == fp:
                                findings.append({
                                    "GroupId": group_id,
                                    "GroupName": group_name,
                                    "Protocol": protocol,
                                    "FromPort": fp,
                                    "ToPort": tp,
                                    "Ipv4": ipv4,
                                    'Ipv6': None
                                })
                                
                    for ip6 in perm.get("Ipv6Ranges", []):
                        ipv6 = ip6.get("CidrIpv6")
                        if ipv6 in open_to_world and protocol == "tcp":
                            if fp in exposed_ports and tp == fp:
                                findings.append({
                                    "GroupId": group_id,
                                    "GroupName": group_name,
                                    "Protocol": protocol,
                                    "FromPort": fp,
                                    "ToPort": tp,
                                    'Ipv6': ipv6,
                                    "Ipv4": None
                                })
        
    except ClientError as e:
        log_client_error(e, "scan_exposed_sg")
        
    return findings

def remediate_exposed_sg(security_groups):
    findings = []
    
    try:
        for sg in security_groups:
            ipv4 = sg["Ipv4"]
            ipv6 = sg["Ipv6"]
            group_id = sg["GroupId"]
            
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

def tag_sg(revoked) -> bool:
    
    for sg in revoked:
        group_id = sg["Revoked"]
        try:
            ec2.create_tags(
                Resources=[group_id],
                Tags=[
                    {"Key": TAG_STATUS_KEY, "Value": "Aegis:Remediated"},
                    {"Key": TAG_LASTFIX_KEY, "Value": f"Aegis:{now_utc_iso()}"}
                ]
            )
            return True
    
        except ClientError as e:
            log_client_error(e, "tag_sg")
            return False
    
    
def actor_meta(detail):
    ui = detail.get("userIdentity", {})
    session_context = ui.get("sessionContext", {})
    attrs = session_context.get("attributes", {})
    
    actor = {
        "Type": ui.get("type", ""),
        "Arn": ui.get("arn", ""),
        "UserName": ui.get("userName"),
        "AccountId": ui.get("accountId", ""),
        "PrincipalId": ui.get("principalId", ""),
        "CreationDate": attrs.get("creationDate", ""),
        "MFA": attrs.get("mfaAuthenticated", "")
    }
    
    return actor

def build_subject() -> str:
    return f"[Aegis/Medium] Security Groups Alert"

def build_message(region, body) -> str:
    return f"""NON-COMPLIANT findings found.

Severity: Medium
Region: {region}

Findings: {body}

Recommended Actions:
- Review the findings listed above.
- Validate wether the info matches with security and compliance requirements.
- Check security group tags for status and date info.
- Remediate any known issues as soon as possible.
- Re-run the audit to match compliance (if needed).
"""

def publish_sns(arn, subject, message) -> None:
    try:
        sns.publish(
            TopicArn=arn,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        log_client_error(e, "publish_sns")

def lambda_handler(event, context):
    logger.info(f"Lambda started!")
    logger.info(f"Event received: {json.dumps(event)}")
    
    detail = event.get("detail", {})
    event_type = detail.get("eventType", {})
    actor = actor_meta(detail)
    ip = detail.get("sourceIpAddress")
    when = now_utc_iso()
    
    exposed = scan_exposed_sg()
    
    if not exposed:
        return {
            "statusCode": 500,
            "message": "COMPLIANT"
        }
        
    logger.info(f"Found: {len(exposed)} open security groups.")   
    logger.info(f"Attempting to remediate...") 
    
    remediate = remediate_exposed_sg(exposed)
    tags = tag_sg(remediate)
    
    body = {
        "Status": "NON-COMPLIANT",
        "EventType": event_type,
        "SourceIpAddress": ip,
        "Time (UTC)": when,
        "Actor": actor,
        "Addedtags": tags,
        "Findings": remediate
    }
    
    
    subject = build_subject()
    message = build_message(
        region=REGION,
        body=json.dumps(body, indent=2)
    )
    
    publish_sns(
        arn=SNS_TOPIC_ARN,
        subject=subject,
        message=message
    )
    
    return {
        "statusCode": 200,
        "body": json.dumps(body)
    }
    
    
    