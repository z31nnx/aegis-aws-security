from botocore.exceptions import ClientError
from datetime import datetime, timezone
import logging 
import boto3
import json 
import os 

REGION = os.getenv("REGION", "us-east-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
TARGET_ROLE_ARNS = json.loads("TARGET_ROLE_ARNS", "[]")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

sns = boto3.client("sns", region_name=REGION)
sts = boto3.client("sts", region_name=REGION)

TAG_STATUS_KEY = "Aegis:Status"
TAG_LASTFIX_KEY = "Aegis:LastFix"

def assume_role(role_arn) -> boto3.Session:
    assume = 