from botocore.exceptions import ClientError
from datetime import datetime, timezone
import logging
import boto3
import json
import os 

REGION = os.getenv("REGION", "us-east-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
QUARANTINE_SG = os.getenv("QUARANTINE_SG", "sg-029c55e700cb433dc")
TARGET_ROLE_ARNS = json.loads(os.getenv("TARGET_ROLE_ARNS", "[]"))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO)

def log_client_error(e: ClientError, where: str) -> None:
    code = e.response["Error"].get("Code", "Unknown code")
    msg = e.response["Error"].get("Message", "No message")
    logger.exception(f"Error caught in {where}: {code} - {msg}")
    
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def describe_instance(ec2, iid) -> list[dict]:
    findings = []
    
    try:
        response = ec2.describe_instances(InstanceIds=[iid])
        for r in response.get("Reservations", []):
            for i in r.get('Instances', []):
                iid = i["InstanceId"]
                state = i["State"]["Name"]
                vpc_id = i["VpcId"]
                subnet_id = i["SubnetId"]
                iam_profile = i.get("IamInstanceProfile", {}).get("Arn", "N/A")
                for block_device in i.get("BlockDeviceMappings", []):
                    volume_id = block_device["Ebs"]["VolumeId"]
                
                for sg in i.get("SecurityGroups", []):
                    group_id = sg["GroupId"]
                    
                findings.append({
                    "InstanceId": iid,
                    "State": state,
                    "VpcId": vpc_id,
                    "SubnetId": subnet_id,
                    "IAMProfile": iam_profile,
                    "VolumeId": volume_id,
                    "GroupId": group_id,
                    "Action": "DescribeInstance",
                    "Status": "Success"
                })
                    
    except ClientError as e:
        log_client_error(e, "describe_instance")
        findings.append({
            "InstanceId": iid,
            "State": state,
            "VpcId": vpc_id,
            "SubnetId": subnet_id,
            "IAMProfile": iam_profile,
            "VolumeId": volume_id,
            "GroupId": group_id,
            "Action": "DescribeInstance",
            "Status": "Failed",
            "Error": e.response["Error"].get("Message", "No message")
        })
        
    return findings

def tags() -> list[dict]:
    return [
        {"Key": "Aegis:Status", "Value": "Quarantined"},
        {"Key": "Aegis:Reason", "Value": "CryptoCurrency:EC2/"},
        {"Key": "Aegis:LastFix", "Value": now_utc_iso()}
    ]
    
def tag_instance(ec2, iid) -> bool:
    findings = []
    
    try:
        ec2.create_tags(
            Resources=[iid],
            Tags=tags()
        )
        findings.append({
            "InstanceId": iid,
            "Action": "CreateTags",
            "Status": "Success"
        })
    except ClientError as e:
        log_client_error(e, "tag_instance")
        findings.append({
            "InstanceId": iid,
            "Action": "CreateTags",
            "Status": "Failed",
            "Error": e.response["Error"].get("Message", "No message")
        })
    
    return findings

def snapshot_instance(ec2, instance) -> list:
    findings = []
    
    for i in instance:
        volume_id = i["VolumeId"]
        iid = i["InstanceId"]
        
        try: 
            ec2.create_snapshot(
                VolumeId=volume_id,
                Description=f"GuardDuty crypto remediation snapshot for {iid}",
                TagSpecifications=[
                    {
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": "Name", "Value": f"{iid}-{volume_id}-CryptoMiningSnapshot"},
                            {"Key": "SourceId", "Value": iid},
                            {"Key": "Aegis:Purpose", "Value": "Forensics"},
                            {"Key": "CreatedBy", "Value": "AegisLambda"},
                            {"Key": "Aegis:Reason", "Value": "CryptoCurrency:EC2/"},
                            {"Key": "Aegis:LastSnapshot", "Value": now_utc_iso() },
                        ]
                    }
                ]
                                )
            
            findings.append({
                "InstanceId": iid,
                "VolumeId": volume_id,
                "Action": "CreateSnapshot",
                "Status": "Success"
            })
            
        except ClientError as e:
            log_client_error(e, "snapshot_instance")
            findings.append({
                "InstanceId": iid,
                "VolumeId": volume_id,
                "Action": "CreateSnapshot",
                "Status": "Failed",
                "Error": e.response["Error"].get("Message", "No message")
            })
            
    return findings

def get_iam_profile_association(ec2, iid) -> str | None:    
    try:
        response = ec2.describe_iam_instance_profile_associations(
            Filters=[
                {
                    "Name": "instance-id",
                    "Values": [iid]
                }
            ]
        )
        
        associations = response.get("IamInstanceProfileAssociations", [])
        if not associations:
            return None 
        
        return associations[0]["AssociationId"]
        
    except ClientError as e:
        log_client_error(e, "get_iam_profile_association")
        return None

def quarantine_instance(ec2, instance, sg_id) -> list:
    findings = []

    for i in instance:
        iid = i["InstanceId"]
        actions = []
        association_id = get_iam_profile_association(ec2, iid)
    
        try:
            if association_id:
                ec2.disassociate_iam_instance_profile(AssociationId=association_id)
                actions.append("DisassociateIAMInstanceProfile")

            ec2.modify_instance_attribute(
                InstanceId=iid,
                Groups=[sg_id]
            )
            actions.append("ReplaceSecurityGroupWithQuarantineSG")

            ec2.stop_instances(
                InstanceIds=[iid]
            )
            actions.append("StopInstance")

            findings.append({
                "InstanceId": iid,
                "Actions": actions,
                "Status": "Success"
            })

        except ClientError as e:
            log_client_error(e, "quarantine_instance")

            findings.append({
                "InstanceId": iid,
                "Actions": actions,
                "Status": "Failed",
                "Error": e.response["Error"].get("Message", "No message")
            })

    return findings
    
def guardduty_event(detail) -> dict:
    resource = detail.get("resource", {}) 
    instance = resource.get("instanceDetails", {})
    
    return {
        "Severity": detail.get("severity"),
        "title": detail.get("title"),
        "InstanceId": instance.get("instanceId"),
        "InstanceType": instance.get("instanceType")
    }
    
def build_subject() -> str:
    return f"[Aegis/High] GuardDuty Crypto Mining Alert"

def build_message(account, region, event, time, findings) -> str:
    return f"""GuardDuty Findings Detected

Finding ID:
Finding type:
Severity: High
Event Name: {event}
Account ID: {account}
Region: {region}
Time (UTC): {time}

Findings: {json.dumps(findings, indent=2)}

Recommended Actions: 
- Review the current findings.
- Review the compromised instance.
- Ensure the instance is (stopped, tagged, quarantined, and snapshotted).
- Validate that remediation succeeded. 
- Escalate if needed.
"""    

def publish_sns(sns, arn, subject, message) -> bool:
    try:
        sns.publish(
            TopicArn=arn,
            Subject=subject,
            Message=message
        )
        return True
    except ClientError as e:
        log_client_error(e, "publish_sns")
        return False
    
def lambda_handler(event, context):
    logger.info(f"Lambda started!")
    logger.info(f"Event received: {json.dumps(event)}")
    logger.info(f"Starting audit...")
    
    sts = boto3.client("sts", region_name=REGION)
    sns = boto3.client("sns", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)
    
    event = event or {}
    detail = event.get("detail", {})
    event_type = detail.get("type", "Unknown")
    severity = event.get("severity")
    description = event.get("description")
    guardduty = guardduty_event(detail) or {}
    iid = guardduty.get("InstanceId", "Unknown")
    
    results = []
    
    source_account = sts.get_caller_identity()["Account"]
    instance = describe_instance(ec2=ec2, iid=iid)
    tag = tag_instance(ec2=ec2, iid=iid)
    snapshot = snapshot_instance(ec2=ec2, instance=instance)
    profile = get_iam_profile_association(ec2=ec2, iid=iid)
    quarantine = quarantine_instance(ec2=ec2, instance=instance, sg_id=QUARANTINE_SG)
    
    results.append({
        "Account": source_account,
        "Instance": instance,
        "Tag": tag,
        "Snapshot": snapshot,
        "Profile": profile,
        "Quarantined": quarantine
    })
    
    print(results)
    
    body = {
        "Results": results
    }
    
    logger.info("Audit complete")
    
    return {
        "statusCode": 200,
        "body": json.dumps(body)
    }

event = {
    "version": "0",
    "id": "test-guardduty-crypto-finding",
    "detail-type": "GuardDuty Finding",
    "source": "aws.guardduty",
    "account": "111122223333",
    "time": "2026-04-29T12:00:00Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
        "schemaVersion": "2.0",
        "accountId": "111122223333",
        "region": "us-east-1",
        "partition": "aws",
        "id": "test-finding-id",
        "arn": "arn:aws:guardduty:us-east-1:111122223333:detector/test-detector-id/finding/test-finding-id",
        "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "resource": {
            "resourceType": "Instance",
            "instanceDetails": {
                "instanceId": "i-068b9faa0d8284eb1",
                "instanceType": "t2.micro",
                "launchTime": "2026-04-29T11:30:00Z",
                "platform": None,
                "productCodes": [],
                "iamInstanceProfile": {
                    "arn": "arn:aws:iam::111122223333:instance-profile/test-instance-profile",
                    "id": "AIPAEXAMPLE"
                },
                "networkInterfaces": [],
                "tags": [
                    {
                        "key": "Name",
                        "value": "aegis-test-instance"
                    }
                ]
            }
        },
        "service": {
            "serviceName": "guardduty",
            "detectorId": "test-detector-id",
            "action": {
                "actionType": "DNS_REQUEST",
                "dnsRequestAction": {
                    "domain": "pool.example-mining-domain.com",
                    "protocol": "UDP",
                    "blocked": False
                }
            },
            "eventFirstSeen": "2026-04-29T11:55:00Z",
            "eventLastSeen": "2026-04-29T11:59:00Z",
            "archived": False,
            "count": 1
        },
        "severity": 8,
        "createdAt": "2026-04-29T12:00:00Z",
        "updatedAt": "2026-04-29T12:00:00Z",
        "title": "EC2 instance is querying a domain name associated with cryptocurrency activity",
        "description": "EC2 instance i-068b9faa0d8284eb1 is querying a domain name associated with cryptocurrency activity."
    }
}

lambda_handler(event, context=None)