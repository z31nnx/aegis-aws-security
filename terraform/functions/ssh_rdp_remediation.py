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

def log_client_error(e: ClientError, where: str) -> None:
    code = e.response["Error"].get("Code", "Unknown code")
    msg = e.response["Error"].get("Message", "No message")
    return logger.exception(f"Error caught in {where}: {code} - {msg}")
    
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
    
    try:
        for sg in security_groups:
            sg_id = sg["GroupId"]
            
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

logger.info(remediate_exposed_sg(scan_exposed_sg()))