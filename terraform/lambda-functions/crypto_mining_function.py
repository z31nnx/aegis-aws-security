from botocore.exceptions import ClientError
from datetime import datetime, timezone
import logging
import boto3
import json
import os 

REGION = os.getenv("REGION", "us-east-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
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

def actor_meta(detail) -> dict: 
    ui = detail.get("userIdentity", {})
    
    return {
        "User": ui.get("userName"),
        "AccountId": ui.get("accountId"),
        "PrincipalId": ui.get("principalId"),
        "Arn": ui.get("arn")
    }
    
def guardduty_event(detail) -> dict:
    resource = detail.get("resource", {}) 
    instance = resource.get("instanceDetails", {})
    
    return {
        "Severity": detail.get("severity"),
        "title": detail.get("title"),
        "InstanceId": instance.get("instanceId"),
        "InstanceType": instance.get("instanceType")
    }
    
def lambda_handler(event, context):
    logger.info(f"Lambda started!")
    logger.info(f"Event received: {json.dumps(event)}")
    logger.info(f"Starting audit...")
    
    sts = boto3.client("sts", region_name=REGION)
    sns = boto3.client("sns", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)
    iam = boto3.client("iam")
    
    event = event or {}
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Uknown")
    event_type = detail.get("type", "Unknown")
    ip = detail.get("sourceIpAddress", "Unknown")
    guardduty = guardduty_event(detail) or {}
    iid = guardduty.get("InstanceId", "Unknown")
    
    results = []
    
    source_account = sts.get_caller_identity()["Account"]
    instance = describe_instance(ec2=ec2, iid="i-018e0f2f275fcff51")
    quarantine = quarantine_instance(ec2=ec2, instance=instance, sg_id="sg-0c7ea10f7f154a0ed")
    
    results.append({
        "Account": source_account,
        "Instance": instance,
        "Quarantined": quarantine
    })
    
    print(results)
    
    body = {
        "Results": results
    }
    
    return {
        "statusCode": 200,
        "body": json.dumps(body)
    }
    
lambda_handler(event=None, context=None)