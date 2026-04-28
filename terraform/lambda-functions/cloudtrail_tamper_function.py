from botocore.exceptions import ClientError
from datetime import datetime, timezone
import logging
import boto3
import json
import os 

REGION = os.getenv("REGION", "us-east-1")
ENVIRONMENT = os.getenv("ENVIRONMENT")
PROJECT = os.getenv("PROJECT")
OWNER = os.getenv("OWNER")
MANAGEDBY = os.getenv("MANAGEDBY")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
TARGET_ROLE_ARNS = json.loads(os.getenv("TARGET_ROLE_ARNS", "[]"))
TRAIL_ARN = os.getenv("TRAIL_ARN")
TRAIL_NAME = os.getenv("TRAIL_NAME")
BUCKET_NAME = os.getenv("BUCKET_NAME")
KMS_KEY_ID = os.getenv("KMS_KEY_ID")
BUCKET_PREFIX = os.getenv("BUCKET_PREFIX", "cloudtrail")
INCLUDE_GLOBAL_SERVICE_EVENTS = os.getenv("INCLUDE_GLOBAL_SERVICE_EVENTS", "true").strip().lower() == "true"
MULTI_REGION = os.getenv("MULTI_REGION", "true").strip().lower() == "true"
LOG_FILE_VALIDATION = os.getenv("LOG_FILE_VALIDATION", "true").strip().lower() == "true"

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
            RoleSessionName="AegisRemediation"
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

def list_trails(cloudtrail) -> list[dict]:
    trails = []
    
    try:
        paginator = cloudtrail.get_paginator("list_trails")
        for page in paginator.paginate():
            for trail in page.get("Trails", []):
                trails.append(trail)
    except ClientError as e:
        log_client_error(e, "list_trails")
        raise 
    
    return trails

def tags() -> list[dict]:
    return [
        {"Key": "Aegis:Status", "Value": "Remediated"},
        {"Key": "Aegis:LastFix", "Value": now_utc_iso()},
        {"Key": "Environment", "Value": ENVIRONMENT},
        {"Key": "Project", "Value": PROJECT},
        {"Key": "Owner", "Value": OWNER},
        {"Key": "ManagedBy", "Value": MANAGEDBY}
    ]
    
def trail_baseline() -> dict:
    baseline = {
        "Name": TRAIL_NAME,
        "S3BucketName": BUCKET_NAME,
        "S3KeyPrefix": BUCKET_PREFIX,
        "IncludeGlobalServiceEvents": INCLUDE_GLOBAL_SERVICE_EVENTS,
        "IsMultiRegionTrail": MULTI_REGION,
        "EnableLogFileValidation": LOG_FILE_VALIDATION,
        "KmsKeyId": KMS_KEY_ID 
    }
    
    return baseline
    
def is_logging(cloudtrail) -> bool:
    try:
        return cloudtrail.get_trail_status(
            Name=TRAIL_ARN
        )["IsLogging"]
        
    except ClientError as e:
        log_client_error(e, "is_logging")
        return False
        
def remediate_logging(cloudtrail) -> bool:
    try:
        cloudtrail.start_logging(
            Name=TRAIL_ARN
        )
        return True
    except ClientError as e:
        log_client_error(e, "remediate_logging")
        return False
    
def is_missing(trails) -> bool:
    trail_arns = [t["TrailARN"] for t in trails]
    if TRAIL_ARN not in trail_arns:
        return True
    
    return False

def remediate_trail(cloudtrail) -> list[dict]:
    findings = []
    
    try: 
        response = cloudtrail.create_trail(
            trail_baseline()
        )

        cloudtrail.add_tags(
            ResourceId=response["TrailARN"],
            TagsList=tags()
        )

        findings.append({
            "Status": "SUCCESS",
            "Action": "CreateTrail",
            "Baseline": trail_baseline()
        })
        
    except ClientError as e:
        log_client_error(e, "create_trail")
        findings.append({
            "Status": "FAILED",
            "Action": "CreateTrail",
            "Baseline": trail_baseline(),
            "Error": e.response["Error"].get("Message", "Unknown message")
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
    
def build_finding(remediation) -> dict:
    
    return {
        "FindingType": "CloudTrailTamper",
        "Resource": {
            "Type": "CloudTrail",
            "CloudTrailARN": TRAIL_ARN,
        },
        "Baseline": remediation.get("Baseline", {}),
        "Remediation": {
            "Action": remediation.get("Action"),
            "Status": remediation.get("Status"),
            "Error": remediation.get("Error")
        }
    }  

def build_subject() -> str:
    return "[Aegis/Critical] CloudTrail Tamper Alert"

def build_message(region, event, time, ip, actor, findings) -> str:
    return f"""CloudTrail Tamper Findings Detected

Severity: CRITICAL
Region: {region}
Event: {event}
Time (UTC): {time}
Source IP: {ip}

Actor: {json.dumps(actor, indent=2)}

Findings: {json.dumps(findings, indent=2)}

Recommended Actions: 
- Review the actor that triggered the event. 
- Confirm the tamper event was expected for testing or unauthorized.
- Validate that remediation succeeded.
- Re-run the audit to confirm CloudTrail baseline.
- Escalate if needed.
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
    
    event = event or {}
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
    ip = detail.get("sourceIPAddress", "Unknown")
    actor = actor_meta(detail)
    time = now_utc_iso()
    
    results = []
    
    source_account = sts.get_caller_identity()["Account"]
    cloudtrail = boto3.client("cloudtrail", region_name=REGION)
    
    account_findings = []
    
    trails = list_trails(cloudtrail=cloudtrail)
    missing = is_missing(trails=trails)

    if missing:
        logger.info(f"Missing trail detected in {source_account}.")
        logger.info("Attempting to remediate")
        remediate = remediate_trail(cloudtrail=cloudtrail)
        
        for rem in remediate:
            finding = build_finding(
                remediation=rem
            )
            account_findings.append(finding)
            
        logging = False

    else:
        logging = is_logging(cloudtrail=cloudtrail)
        if logging == False:
            start_logging = remediate_logging(cloudtrail=cloudtrail)

            finding = build_finding(
                remediation={
                    "Status": "SUCCESS" if start_logging else "FAILED",
                    "Action": "StartLogging"
                }
            )
            account_findings.append(finding)
    
    results.append({
        "Account": source_account,
        "Logging": logging,
        "Findings": account_findings
    })
    
    if TARGET_ROLE_ARNS:
        for role_arn in TARGET_ROLE_ARNS:
            try:
                session = assume_role(role_arn=role_arn)
                target_account = session.client("sts").get_caller_identity()["Account"]
                logger.info(f"Scanning target account: {target_account}")
                target_cloudtrail = session.client("cloudtrail", region_name=REGION)
                
                account_findings = []
                
                trails = list_trails(cloudtrail=target_cloudtrail)
                missing = is_missing(trails=trails)

                if missing:
                    logger.info(f"Missing trail detected in target account: {target_account}")
                    remediate = remediate_trail(cloudtrail=target_cloudtrail)
                    
                    for rem in remediate:
                        finding = build_finding(remediation=rem)
                        account_findings.append(finding)

                    logging = False

                else:
                    logging = is_logging(cloudtrail=target_cloudtrail)
                    
                    if logging == False:
                        start_logging = remediate_logging(cloudtrail=target_cloudtrail)

                        finding = build_finding(
                            remediation={
                                "Status": "SUCCESS" if start_logging else "FAILED",
                                "Action": "StartLogging"
                            }
                        )
                        account_findings.append(finding)
                        
                results.append({
                    "Account": target_account,
                    "Logging": logging,
                    "Findings": account_findings
                })
            
            except ClientError as e:
                log_client_error(e, f"Target account processing: {role_arn}")
                results.append({
                    "Status": "ERROR",
                    "RoleArn": role_arn,
                    "Reason": "AssumeRole or account processing failed"
                })
                continue
    
    body = {
        "Results": results
    }

    if SNS_TOPIC_ARN:
        subject = build_subject()
        message = build_message(
            region=REGION,
            event=event_name,
            time=time,
            ip=ip,
            actor=actor,
            findings=results
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