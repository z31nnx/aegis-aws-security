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
INCLUDE_GLOBAL_SERVICE_EVENTS = os.getenv("INCLUDE_GLOBAL_SERVICE_EVENTS").strip().lower() == "true"
MULTI_REGION = os.getenv("MULTI_REGION").strip().lower() == "true"
LOG_FILE_VALIDATION = os.getenv("LOG_FILE_VALIDATION").strip().lower() == "true"

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
    return {
        "Name": TRAIL_NAME,
        "S3BucketName": BUCKET_NAME,
        "S3KeyPrefix": BUCKET_PREFIX,
        "IncludeGlobalServiceEvents": INCLUDE_GLOBAL_SERVICE_EVENTS,
        "IsMultiRegionTrail": MULTI_REGION,
        "TrailARN": TRAIL_ARN,
        "LogFileValidationEnabled": LOG_FILE_VALIDATION,
        "KmsKeyId": KMS_KEY_ID,
        "TagsList": tags()
    }
    
def is_logging(cloudtrail) -> bool:
    try:
        cloudtrail.get_trail_status(
            Name=TRAIL_ARN
        )["IsLogging"]
        
    except ClientError as e:
        log_client_error(e, "is_logging")
        
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
        cloudtrail.create_trail(
            trail_baseline()
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
        "Remediation": {
            "Action": remediation.get("Action"),
            "Status": remediation.get("Status"),
            "Error": remediation.get("Error")
        }
    }   
    
    
def lambda_handler(event, context):
    logger.info("Lambda started!")
    logger.info(f"Event received: {json.dumps(event)}")
    logger.info("Starting audit...")
    
    event = event or {}
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Unknown")
    ip = detail.get("sourceIPAddress", "Unknown")
    actor = actor_meta(detail)
    when = now_utc_iso()
    
    results = []
    
    source_account = sts.get_caller_identity()["Account"]
    cloudtrail = boto3.client("cloudtrail", region_name=REGION)
    
    trails = list_trails(cloudtrail=cloudtrail)
    logging = is_logging(cloudtrail=cloudtrail)
    
    if logging == False:
        start_logging = remediate_logging()
        
    missing = is_missing(trails=trails)
    if missing:
        logger.info(f"Missing trail detected in {source_account}.")
        logger.info("Attempting to remediate")
        remediate = remediate_trail()
    
    account_findings = []
    finding = build_finding(
        remediation=remediate
    )
    account_findings.append(finding)
    
    results.append({
        "Account": source_account,
        "Logging": logging,
        "Findings": account_findings
    })
    
    body = {
        "Results": results
    }
    
    return {
        "statusCode": 200,
        "body": json.dumps(body)
    }