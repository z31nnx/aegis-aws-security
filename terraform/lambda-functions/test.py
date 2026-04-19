from botocore.exceptions import ClientError
from datetime import datetime, timezone
import logging
import boto3
import json
import os

REGION = os.getenv("REGION", "us-east-1")
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
ROLE_ARNS = json.loads(os.getenv("ROLE_ARNS", "[]"))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.basicConfig(level=logging.INFO)

sts = boto3.client("sts", region_name=REGION)

TAG_STATUS_KEY = "Aegis:Status"
TAG_LASTFIX_KEY = "Aegis:LastFix"

