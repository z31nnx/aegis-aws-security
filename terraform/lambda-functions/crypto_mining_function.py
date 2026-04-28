from botocore.exceptions import ClientError
from datetime import datetime, timezone
import logging
import boto3
import json
import os 

REGION = os.getenv("REGION", "us-east-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
TARGET_ROLE_ARNS = json.loads("TARGET_ROLE_ARNS", "[]")

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO)

sts = boto3.client("sts", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)
iam = boto3.client("iam")

def log_client_error(e: ClientError, where: str) -> None:
    code = e.response["Error"].get("Code", "Unknown code")
    msg = e.response["Error"].get("Message", "No message")
    logger.exception(f"Error caught in {where}: {code} - {msg}")
    
def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def tags() -> list[dict]:
    return [
        {"Key": "Aegis:Status", "Value": "remediated"},
        {"Key": "Aegis:Reason", "Value": "CryptoCurrency:EC2/"},
        {"Key": "Aegis:LastFix", "Value": now_utc_iso()}
    ]

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
    
    return {
        "Severity": detail.get("severity"),
        "title": detail.get("title")
    }
    
def lambda_handler(event, context):
    logger.info(f"Lambda started!")
    logger.info(f"Event received: {json.dumps(event)}")
    logger.info(f"Starting audit...")
    
    event = event or {}
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "Uknown")
    event_type = detail.get("type", "Unknown")
    ip = detail.get("sourceIpAddress", "Unknown")
    
    results = []
    
    body = {
        "Results": results
    }
    
    return {
        "statusCode": 200,
        "body": json.dumps(body)
    }