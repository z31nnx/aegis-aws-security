from botocore.exceptions import ClientError
from datetime import datetime, timezone
import json, logging, os, boto3

REGION = os.getenv("REGION", "us-east-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

TAG_STATUS_KEY = "Aegis:Status"
TAG_LASTFIX_KEY = "Aegis:LastFix"

if not SNS_TOPIC_ARN:
    raise RuntimeError("Required: missing SNS_TOPIC_ARN")


def log_client_error(e: ClientError, where: str) -> None:
    code = e.response["Error"].get("Code", "Unknown code")
    msg = e.response["Error"].get("Message", "No message")
    logger.exception(f"Error caught in {where}: {code} - {msg}")


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def scan_exposed_sg():
    findings = []
    
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for p in paginator.paginate():
            for sg in p.get("SecurityGroups", []):
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName", "unnamed")
                
                for inbound in sg.get("IpPermissions", []):
                    ip_protocol = inbound.get("IpProtocol", "All")
                    from_port = inbound.get("FromPort")
                    to_port = inbound.get("ToPort")
                    sensitive_ports = (22, 3389)
                    
                    if ip_protocol == "tcp":
                        if from_port in sensitive_ports and to_port == from_port:
                            
                            for ip in inbound.get("IpRanges", []):
                                ipv4 = ip.get("CidrIp")
                                if ipv4 == "0.0.0.0/0":
                                    findings.append({
                                        "GroupId": sg_id,
                                        "GroupName": sg_name,
                                        "Protocol": ip_protocol,
                                        "FromPort": from_port,
                                        "ToPort": to_port,
                                        "Ipv4": ipv4,
                                        "Ipv6": None
                                    })
                            
                            for ip in inbound.get("Ipv6Ranges", []):
                                ipv6 = ip.get("CidrIpv6")
                                if ipv6 == "::/0":
                                    findings.append({
                                        "GroupId": sg_id,
                                        "GroupName": sg_name,
                                        "Protocol": ip_protocol,
                                        "FromPort": from_port,
                                        "ToPort": to_port,
                                        "Ipv4": None,
                                        "Ipv6": ipv6
                                    })
                
    except ClientError as e:
        log_client_error(e, "scan_exposed_sg")
        
    return findings


def remediate_exposed_sg(security_groups):
    findings = []
    
    for sg in security_groups:
        sg_id = sg["GroupId"]
        
        try:
            if sg["Ipv4"]:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": sg["Protocol"],
                            "FromPort": sg["FromPort"],
                            "ToPort": sg["ToPort"],
                            "IpRanges": [
                                {
                                    "CidrIp": sg["Ipv4"]
                                }
                            ]
                        }
                    ]
                )
            
            elif sg["Ipv6"]:
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": sg["Protocol"],
                            "FromPort": sg["FromPort"],
                            "ToPort": sg["ToPort"],
                            "Ipv6Ranges": [
                                {
                                    "CidrIpv6": sg["Ipv6"]
                                }
                            ]
                        }
                    ]
                )

            findings.append({
                "Revoked": sg_id,
                "GroupName": sg["GroupName"],
                "FromPort": sg["FromPort"],
                "ToPort": sg["ToPort"],
                "Ipv4": sg["Ipv4"],
                "Ipv6": sg["Ipv6"]
            })
            
        except ClientError as e:
            log_client_error(e, "remediate_exposed_sg")
        
    return findings


def tag_sg(security_groups):
    success = True
    
    for sg in security_groups:
        group_id = sg["GroupId"]
        
        try:
            ec2.create_tags(
                Resources=[group_id],
                Tags=[
                    {"Key": TAG_STATUS_KEY, "Value": "Remediated"},
                    {"Key": TAG_LASTFIX_KEY, "Value": now_iso_utc()},
                ]
            )
        except ClientError as e:
            log_client_error(e, "tag_sg")
            success = False
            
    return success


def actor_metadata(detail):
    ui = detail.get("userIdentity", {})
    actor = {
        "type": ui.get("type", "unknown"),
        "accountId": ui.get("accountId", ""),
        "arn": ui.get("arn", ""),
        "userName": ui.get("userName", ""),
        "principalId": ui.get("principalId", "") 
    }
    
    return actor


def build_subject():
    return "[Aegis/Medium] NON-COMPLIANT Security Group(s) Alert"


def build_message(region, body):
    return f"""Exposed SSH/RDP findings found.

Severity: Medium
Region: {region}

Findings: {body}

Recommended Actions:
- Review the findings listed above.
- Validate whether the resource configuration matches security and compliance requirements.
- Remediate any confirmed issues as soon as possible.
- Re-run the audit after changes are applied to verify compliance (if needed).
"""


def sns_publish(arn, subject, message):
    try:
        sns.publish(
            TopicArn=arn,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        log_client_error(e, "sns_publish")
        return


def lambda_handler(event, context):
    logger.info("Lambda started!")
    logger.info(f"Event received: {json.dumps(event)}")
    logger.info("Starting audit...")
    
    detail = event.get("detail", {})
    event_type = detail.get("eventName", "UnknownEvent")
    region = detail.get("awsRegion", REGION)
    actor = actor_metadata(detail)
    ip = detail.get("sourceIpAddress", "unknown")
    when = now_iso_utc()
    
    exposed = scan_exposed_sg() or []
    logger.info(f"Exposed findings found: {len(exposed)}")

    body = {
        "Status": "NON-COMPLIANT" if exposed else "COMPLIANT",
        "Time (UTC)": when,
        "Region": region,
        "Remediated": False
    }

    if exposed:
        logger.info("Found open SSH/RDP. Initiating remediation...")
        remediated = remediate_exposed_sg(exposed)
        logger.info(f"Remediated findings count: {len(remediated)}")

        tag_success = tag_sg(exposed)
        logger.info(f"Tagging completed: {tag_success}")

        body.update({
            "EventType": event_type,
            "Actor": actor,
            "Source Ip": ip,
            "Remediated": True,
            "Tagged": tag_success,
            'Total Findings': len(remediated),
            "Findings": remediated
        })

    subject = build_subject()
    message = build_message(region=region, body=json.dumps(body, indent=2))

    sns_publish(
        arn=SNS_TOPIC_ARN,
        subject=subject,
        message=message
    )

    return {
        "statusCode": 200,
        "body": json.dumps(body)
    }