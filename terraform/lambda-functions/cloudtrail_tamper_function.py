from botocore.exceptions import ClientError
from datetime import datetime, timezone
import logging 
import boto3
import json 
import os 

REGION = os.getenv("REGION", "us-east-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
TRAIL_NAME = os.getenv("TRAIL_NAME")
TRAIL_ARN = os.getenv("TRAIL_ARN", "arn:aws:cloudtrail:us-east-1:070593202443:trail/security-aegis-central-security-trail")
BUCKET_NAME = os.getenv("BUCKET_NAME")
KMS_KEY_ID = os.getenv("KMS_KEY_ID")
BUCKET_PREFIX = os.getenv("BUCKET_PREFIX", "cloudtrail")
INCLUDE_GLOBAL_SERVICE_EVENTS = os.getenv("INCLUDE_GLOBAL_SERVICE_EVENTS", "True").strip().lower() == "true"
MULTI_REGION = os.getenv("MULTI_REGION", "True").strip().lower() == "true"
LOG_FILE_VALIDATION = os.getenv("LOG_FILE_VALIDATION", "True").strip().lower() == "true"
TARGET_ROLE_ARNS = json.loads(os.getenv("TARGET_ROLE_ARNS", "[]"))

#if not all([SNS_TOPIC_ARN, TRAIL_ARN, TRAIL_NAME, BUCKET_NAME, KMS_KEY_ID]):
#    raise RuntimeError("Required: missing environments")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

sts = boto3.client("sts", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)

def log_client_error(e: ClientError, where: str) -> None:
    code = e.response["Error"].get("Code", "Unknown code")
    msg = e.response["Error"].get("Message", "No message")
    logger.exception(f"Error caught in {where}: {code} - {msg}")

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def tags() -> list[dict]:
    return [
        {"Key": "Aegis:Status", "Value": "Remediated"},
        {"Key": "Aegis:LastFix", "Value": now_utc_iso()}
    ]

def assume_role(role_arn, session_name) -> boto3.Session:
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
    
def trail_baseline() -> dict:
    return {
        "Name": TRAIL_NAME,
        "S3BucketName": BUCKET_NAME,
        "S3KeyPrefix": BUCKET_PREFIX,
        "IncludeGlobalServiceEvents": INCLUDE_GLOBAL_SERVICE_EVENTS,
        "IsMultiRegionTrail": MULTI_REGION,
        "LogFileValidationEnabled": LOG_FILE_VALIDATION,
        "KmsKeyId": KMS_KEY_ID
    }
    
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

def is_missing(trails) -> bool:
    trail_arns = [t["TrailARN"] for t in trails]
    if TRAIL_ARN not in trail_arns:
        return True
    
    return False
    
def lambda_handler(event, context):
    logger.info("Lambda started!")
    logger.info(f"Event received: {json.dumps(event)}")
    logger.info(f"Starting audit...")
    
    event = event or {}
    when = now_utc_iso()
    
    results = []
    
    source_cloudtrail = boto3.client("cloudtrail", region_name=REGION)
    source_account = sts.get_caller_identity()["Account"]
    
    trails = list_trails(cloudtrail=source_cloudtrail)
    missing = is_missing(trails=trails)
    
    if missing == True:
        logger.info("Missing trail detected")
    
    if TARGET_ROLE_ARNS:
        for role_arn in TARGET_ROLE_ARNS:
            try:
                session = assume_role(role_arn=role_arn, session_name="AegisRemediation")
                target_account = session.client("sts", region_name=REGION).get_caller_identity()["Account"]
                target_cloudtrail = session.client("cloudtrail", region_name=REGION)
                
            except ClientError as e:
                log_client_error(e, f"Failed to assume role: {role_arn}")
                results.append({
                    "Status": "ERROR",
                    "RoleArn": role_arn,
                    "Reason": "AssumeRole or Scan failed"
                })
                
                continue
    
    body = {
        "Results": results
    }
    
    return {
        "statusCode": 200,
        "body": json.dumps(body)
    }
    
lambda_handler(event=None, context=None)