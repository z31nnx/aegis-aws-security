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

sts = boto3.client("sts", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

def log_client_error(e: ClientError, where: str) -> None:
    code = e.response["Error"].get("Code", "Unknown code")
    msg = e.response["Error"].get("Message", "No message")
    logger.exception(f"Error caught in {where}: {code} - {msg}")
    
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
            "Action": "DescribeInstance",
            "Status": "Failed",
            "Error": e.response["Error"].get("Message", "No message")
        })
        
    return findings

def get_quarantine_sg(ec2, vpc_id) -> str | None:
    try:
        response = ec2.describe_security_groups(
            Filters=[
                {
                    "Name": "vpc-id",
                    "Values": [vpc_id]
                },
                {
                    "Name": "tag:Project",
                    "Values": ["aegis"]
                },
                {
                    "Name": "tag:Purpose",
                    "Values": ["quarantine"]
                }
            ]
        )

        security_groups = response.get("SecurityGroups", [])

        if not security_groups:
            return None

        return security_groups[0]["GroupId"]

    except ClientError as e:
        log_client_error(e, "get_quarantine_sg")
        return None

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

def quarantine_instance(ec2, instance) -> list:
    findings = []

    for i in instance:
        iid = i["InstanceId"]
        vpc_id = i["VpcId"]
        actions = []
        association_id = get_iam_profile_association(ec2, iid)
        sg_id = get_quarantine_sg(ec2, vpc_id)

        if not sg_id:
            findings.append({
                "InstanceId": iid,
                "VpcId": vpc_id,
                "Action": "FindQuarantineSG",
                "Status": "Failed",
                "Error": "No Aegis quarantine security group found in the instance VPC"
            })
            continue
    
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
                "VpcId": vpc_id,
                "QuarantineSecurityGroup": sg_id,
                "Actions": actions,
                "Status": "Success"
            })

        except ClientError as e:
            log_client_error(e, "quarantine_instance")

            findings.append({
                "InstanceId": iid,
                "VpcId": vpc_id,
                "QuarantineSecurityGroup": sg_id,
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

def build_message(description, finding_id, finding_type, severity, region, time, body) -> str:
    return f"""GuardDuty Findings Detected

Description: {description}

Finding ID: {finding_id}
Finding type: {finding_type}
Severity: {severity}
Region: {region}
Time (UTC): {time}

Findings: {json.dumps(body, indent=2)}

Recommended Actions: 
- Review the current findings.
- Review the compromised instance.
- Ensure the instance is (stopped, tagged, quarantined, and snapshotted).
- Validate that remediation succeeded. 
- Escalate if needed.
"""    

def publish_sns(arn, subject, message) -> bool:
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
    
    event = event or {}
    detail = event.get("detail", {})
    finding_type = detail.get("type", "Unknown")
    finding_id = event.get("id")
    severity = detail.get("severity")
    description = detail.get("description")
    guardduty = guardduty_event(detail) or {}
    iid = guardduty.get("InstanceId", "Unknown")
    region = detail.get("region") or event.get("region") or REGION
    finding_account = detail.get("accountId") or event.get("account")
    time = now_utc_iso()
    
    results = []
    
    source_account = sts.get_caller_identity()["Account"]

    if source_account == finding_account:
        ec2 = boto3.client("ec2", region_name=region)

        instance = describe_instance(ec2=ec2, iid=iid)

        if not instance or instance[0].get("Status") == "Failed":
            results.append({
                "Account": source_account,
                "Instance": instance,
                "Status": "Skipped",
                "Reason": "Instance not found or describe failed"
            })
        else:
            tag = tag_instance(ec2=ec2, iid=iid)
            snapshot = snapshot_instance(ec2=ec2, instance=instance)
            profile = get_iam_profile_association(ec2=ec2, iid=iid)
            quarantine = quarantine_instance(ec2=ec2, instance=instance)
            
            results.append({
                "Account": source_account,
                "Instance": instance,
                "Tag": tag,
                "Snapshot": snapshot,
                "Profile": profile,
                "Quarantined": quarantine
            })
    else:
        logger.info(f"Skipping source account remediation. Finding belongs to account {finding_account}, source account is {source_account}")
    
    if TARGET_ROLE_ARNS:
        for role_arn in TARGET_ROLE_ARNS:
            role_account = role_arn.split(":")[4]

            if role_account != finding_account:
                logger.info(f"Skipping role {role_arn}. Finding belongs to account {finding_account}")
                continue

            try:
                logger.info(f"Multi account: Assuming target role for account {finding_account}")
                session = assume_role(role_arn=role_arn)
                target_account = session.client("sts", region_name=region).get_caller_identity()["Account"]
                target_ec2 = session.client("ec2", region_name=region)
                
                instance = describe_instance(ec2=target_ec2, iid=iid)

                if not instance or instance[0].get("Status") == "Failed":
                    results.append({
                        "Account": target_account,
                        "Instance": instance,
                        "Status": "Skipped",
                        "Reason": "Instance not found or describe failed"
                    })
                    continue

                tag = tag_instance(ec2=target_ec2, iid=iid)
                snapshot = snapshot_instance(ec2=target_ec2, instance=instance)
                profile = get_iam_profile_association(ec2=target_ec2, iid=iid)
                quarantine = quarantine_instance(ec2=target_ec2, instance=instance)
                
                results.append({
                    "Account": target_account,
                    "Instance": instance,
                    "Tag": tag,
                    "Snapshot": snapshot,
                    "Profile": profile,
                    "Quarantined": quarantine
                })
            except ClientError as e:
                log_client_error(e, "lambda_handler")
                results.append({
                    "Status": "Error",
                    "RoleArn": role_arn,
                    "Reason": "AssumeRole or account processing failed"
                })
                continue
    
    body = {
        "Results": results
    }
    
    logger.info("Audit complete")
    
    if SNS_TOPIC_ARN:
        subject = build_subject()
        message = build_message(
            description=description, 
            finding_id=finding_id, 
            finding_type=finding_type,
            severity=severity, 
            region=region, 
            time=time, 
            body=body)
        publish_sns(arn=SNS_TOPIC_ARN, subject=subject, message=message)
    
    print(results)
    
    return {
        "statusCode": 200,
        "body": json.dumps(body)
    }